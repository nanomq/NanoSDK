#include "quic_api.h"
#include "core/nng_impl.h"
#include "msquic.h"
#include "nng/mqtt/mqtt_client.h"
#include "supplemental/mqtt/mqtt_msg.h"

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define QUIC_API_C_DEBUG 0
#define QUIC_API_C_INFO 0

#if QUIC_API_C_DEBUG
#define qdebug(fmt, ...)                                                 \
	do {                                                            \
		printf("[%s]: " fmt "", __FUNCTION__, ##__VA_ARGS__); \
	} while (0)
#else
#define qdebug(fmt, ...) do {} while(0)
#endif

#if QUIC_API_C_INFO
#define qinfo(fmt, ...)                                                 \
	do {                                                            \
		printf("[%s]: " fmt "", __FUNCTION__, ##__VA_ARGS__); \
	} while (0)
#else
#define qinfo(fmt, ...) do {} while(0)
#endif

typedef struct quic_strm_s quic_strm_t;

struct quic_strm_s {
	HQUIC    stream;
	void    *pipe;
	nni_mtx  mtx;
	nni_list sendq;
	nni_list recvq;
	nni_aio *txaio;
	nni_aio *rxaio;
	nni_sock *sock;
	bool     closed;
	nni_lmq  recv_messages; // recv messages queue
	nni_lmq  send_messages; // send messages queue

	nni_aio  rraio; // Use for re-receive when packet length is not enough
	uint32_t rxlen; // Length received
	uint32_t rwlen; // Length wanted
	uint8_t  rxbuf[5];
	nni_msg *rxmsg; // nng_msg for received

	uint8_t  rticket[2048];
	uint16_t rticket_sz;
	bool     rticket_active;
	nng_url *url_s;
};

// Config for msquic
const QUIC_REGISTRATION_CONFIG RegConfig = { "mqtt",
	QUIC_EXECUTION_PROFILE_LOW_LATENCY };
const QUIC_BUFFER     Alpn = { sizeof("mqtt") - 1, (uint8_t *) "mqtt" };
const QUIC_API_TABLE *MsQuic;
HQUIC                 Registration;
HQUIC                 Configuration;

quic_strm_t *GStream = NULL;

nni_proto *g_quic_proto;

static BOOLEAN LoadConfiguration(BOOLEAN Unsecure);
static int     quic_strm_start(HQUIC Connection, void *Context, HQUIC *Streamp, bool active);
static int     quic_strm_close(HQUIC Connection, HQUIC Stream);
static void    quic_strm_send_cancel(nni_aio *aio, void *arg, int rv);
static void    quic_strm_send_start(quic_strm_t *qstrm);
static void    quic_strm_recv_cb();
static void    quic_strm_init(quic_strm_t *qstrm);
static void    quic_strm_fini(quic_strm_t *qstrm);
static void    quic_strm_recv_start(void *arg);
static int     quic_reconnect(quic_strm_t *qstrm);

// Helper function to load a client configuration.
static BOOLEAN
LoadConfiguration(BOOLEAN Unsecure)
{
	QUIC_SETTINGS Settings = { 0 };
	// Configures the client's idle timeout.
	Settings.IdleTimeoutMs       = 60*1000;
	Settings.IsSet.IdleTimeoutMs = TRUE;

	// Configures a default client configuration, optionally disabling
	// server certificate validation.
	QUIC_CREDENTIAL_CONFIG CredConfig;
	memset(&CredConfig, 0, sizeof(CredConfig));
	CredConfig.Type  = QUIC_CREDENTIAL_TYPE_NONE;
	CredConfig.Flags = QUIC_CREDENTIAL_FLAG_CLIENT;
	if (Unsecure) {
		CredConfig.Flags |=
		    QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
	}

	// Allocate/initialize the configuration object, with the configured
	// ALPN and settings.
	QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
	if (QUIC_FAILED(
	        Status = MsQuic->ConfigurationOpen(Registration, &Alpn, 1,
	            &Settings, sizeof(Settings), NULL, &Configuration))) {
		qdebug("ConfigurationOpen failed, 0x%x!\n", Status);
		return FALSE;
	}

	// Loads the TLS credential part of the configuration. This is required
	// even on client side, to indicate if a certificate is required or
	// not.
	if (QUIC_FAILED(Status = MsQuic->ConfigurationLoadCredential(
	                    Configuration, &CredConfig))) {
		qdebug("ConfigurationLoadCredential failed, 0x%x!\n", Status);
		return FALSE;
	}

	return TRUE;
}

static void
quic_strm_init(quic_strm_t *qstrm)
{
	qstrm->closed = false;
	qstrm->rxaio  = NULL;
	qstrm->txaio  = NULL;
	nni_mtx_init(&qstrm->mtx);
	nni_aio_list_init(&qstrm->sendq);
	nni_aio_list_init(&qstrm->recvq);

	nni_lmq_init(&qstrm->recv_messages, NNG_MAX_RECV_LMQ);
	nni_lmq_init(&qstrm->send_messages, NNG_MAX_SEND_LMQ);

	nni_aio_init(&qstrm->rraio, quic_strm_recv_start, qstrm);

	qstrm->rxlen = 0;
	qstrm->rxmsg = NULL;

	qstrm->url_s = NULL;
	qstrm->rticket_sz = 0;
	qstrm->rticket_active = false;
}

static void
quic_strm_fini(quic_strm_t *qstrm)
{
	if (qstrm->rxmsg)
		free(qstrm->rxmsg);
	return;
}

// The clients's callback for stream events from MsQuic.
// New recv cb of quic transport
_IRQL_requires_max_(DISPATCH_LEVEL)
    _Function_class_(QUIC_STREAM_CALLBACK) QUIC_STATUS QUIC_API
QuicStreamCallback(_In_ HQUIC Stream, _In_opt_ void *Context,
        _Inout_ QUIC_STREAM_EVENT *Event)
{
	quic_strm_t *qstrm = Context;
	int rlen, n;
	uint32_t remain_len;
	uint8_t *rbuf, usedbytes;
	nni_msg *rmsg, *smsg;
	nni_aio *aio;

	switch (Event->Type) {
	case QUIC_STREAM_EVENT_SEND_COMPLETE:
		// A previous StreamSend call has completed, and the context is
		// being returned back to the app.
		free(Event->SEND_COMPLETE.ClientContext);
		qinfo("[strm][%p] Data sent\n", Stream);

		// Get aio from sendq and finish
		nni_mtx_lock(&qstrm->mtx);
		if ((aio = nni_list_first(&qstrm->sendq)) != NULL) {
			nni_aio_list_remove(aio);
			quic_strm_send_start(qstrm);
			nni_mtx_unlock(&qstrm->mtx);
			smsg = nni_aio_get_msg(aio);
			nni_msg_free(smsg);
			nni_aio_finish(aio, 0, 0);
			break;
		}
		quic_strm_send_start(qstrm);
		nni_mtx_unlock(&qstrm->mtx);
		break;
	case QUIC_STREAM_EVENT_RECEIVE:
		// Data was received from the peer on the stream.
		rbuf = Event->RECEIVE.Buffers->Buffer;
		rlen = Event->RECEIVE.Buffers->Length;
		uint8_t count = Event->RECEIVE.BufferCount;

		qinfo("[strm][%p] Data received\n", Stream);
		qdebug("Body is [%d]-[0x%x 0x%x].\n", rlen, *(rbuf), *(rbuf + 1));

		// Not get enough len, wait to be re-schedule
		if (Event->RECEIVE.Buffers->Length + qstrm->rxlen < qstrm->rwlen || count == 0) {
			nni_aio * aio = &qstrm->rraio;
			nni_aio_finish(aio, 0, 1);
			// TODO I'am not sure if the buffer in msquic would be free
			return QUIC_STATUS_PENDING;
		}

		qdebug("before rxlen %d rwlen %d.\n", qstrm->rxlen, qstrm->rwlen);

		// Already get 2 Bytes
		if (qstrm->rxlen == 0) {
			n = 2; // new
			memcpy(qstrm->rxbuf, rbuf, n);
			qstrm->rxlen = 0 + n;
			MsQuic->StreamReceiveComplete(qstrm->stream, n);
			if (qstrm->rxbuf[1] == 0) {
				// 0 remaining length could be
				// PINGRESP/DISCONNECT
				if (0 != nng_msg_alloc(&qstrm->rxmsg, 0)) {
					qdebug("error in msg allocated.\n");
				}
				nni_msg_header_append(
				    qstrm->rxmsg, qstrm->rxbuf, 2);
				goto upload;
			}
			if (qstrm->rxbuf[1] == 2)
				qstrm->rwlen = n + 2; // Only this case exclude
			else
				qstrm->rwlen = n + 3;

			// Wait to be re-schedule
			aio = &qstrm->rraio;
			nni_aio_finish(aio, 0, 1);
			// TODO I'am not sure if the buffer in msquic would be free
			qdebug("1after  rxlen %d rwlen %d.\n", qstrm->rxlen, qstrm->rwlen);
			return QUIC_STATUS_PENDING;
		}

		// Already get 4 Bytes
		if (qstrm->rxbuf[1] == 2 && qstrm->rwlen == 4) {
			// Handle 4 bytes msg
			n = 2; // new
			memcpy(qstrm->rxbuf + 2, rbuf, n);
			qstrm->rxlen += n;
			MsQuic->StreamReceiveComplete(qstrm->stream, n);

			// Compose msg
			if (0 != nng_msg_alloc(&qstrm->rxmsg, 4)) {
				qdebug("error in msg allocated.\n");
			}

			nni_msg_header_clear(qstrm->rxmsg);
			nni_msg_clear(qstrm->rxmsg);
			// Copy Header
			nni_msg_header_append(qstrm->rxmsg, qstrm->rxbuf, 2);
			// Copy Body
			nni_msg_append(qstrm->rxmsg, qstrm->rxbuf + 2, 2);

			// Done
			qdebug("2after  rxlen %d rwlen %d.\n", qstrm->rxlen, qstrm->rwlen);
		}

		// Already get 5 Bytes
		if (qstrm->rxbuf[1] > 0x02 && qstrm->rwlen == 5) {
			n = 3; // new
			memcpy(qstrm->rxbuf + 2, rbuf, n);
			qstrm->rxlen += n;
			MsQuic->StreamReceiveComplete(qstrm->stream, n);

			usedbytes = 0;
			if (0 != mqtt_get_remaining_length(qstrm->rxbuf, qstrm->rxlen, &remain_len, &usedbytes)) {
				qdebug("error in get remain_len.\n");
			}
			if (0 != nng_msg_alloc(&qstrm->rxmsg, 1 + usedbytes + remain_len)) {
				qdebug("error in msg allocated.\n");
			}
			qstrm->rwlen = remain_len + usedbytes + 1;

			if (qstrm->rxbuf[1] == 0x03) {
				nni_msg_header_clear(qstrm->rxmsg);
				nni_msg_clear(qstrm->rxmsg);
				// Copy Header
				nni_msg_header_append(qstrm->rxmsg, qstrm->rxbuf, 2);
				// Copy Body
				nni_msg_append(qstrm->rxmsg, qstrm->rxbuf + 2, 3);
			} else {
				// Wait to be re-schedule
				nni_aio * aio = &qstrm->rraio;
				nni_aio_finish(aio, 0, 1);
				// TODO I'am not sure if the buffer in msquic would be free
				qdebug("3after  rxlen %d rwlen %d.\n", qstrm->rxlen, qstrm->rwlen);
				return QUIC_STATUS_PENDING;
			}
		}

		// Already get remain_len Bytes
		if (qstrm->rwlen > 0x05 && qstrm->rxmsg != NULL) {
			usedbytes = 0;
			if (0 != mqtt_get_remaining_length(qstrm->rxbuf, qstrm->rxlen, &remain_len, &usedbytes)) {
				qdebug("error in get remain_len.\n");
			}
			n = 1 + usedbytes + remain_len - 5; // new

			nni_msg_header_clear(qstrm->rxmsg);
			nni_msg_clear(qstrm->rxmsg);
			// Copy Header
			nni_msg_header_append(qstrm->rxmsg, qstrm->rxbuf, 1 + usedbytes);
			// Copy Body
			nni_msg_append(qstrm->rxmsg,
				qstrm->rxbuf + (1 + usedbytes), 5 - (1 + usedbytes));
			nni_msg_append(qstrm->rxmsg, rbuf, n);

			qstrm->rxlen += n;
			MsQuic->StreamReceiveComplete(qstrm->stream, n);
		}
		qdebug("4after  rxlen %d rwlen %d.\n", qstrm->rxlen, qstrm->rwlen);

upload:		// get aio and trigger cb of protocol layer
		nni_mtx_lock(&qstrm->mtx);
		nni_aio *aio = nni_list_first(&qstrm->recvq);
		nni_aio_list_remove(aio);
		nni_mtx_unlock(&qstrm->mtx);

		if (aio != NULL) {
			// Set msg and remove from list and finish
			nni_aio_set_msg(aio, qstrm->rxmsg);
			qstrm->rxmsg = NULL;
			nni_aio_finish(aio, 0, 0);
		}
		return QUIC_STATUS_PENDING;

	case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
		// The peer gracefully shut down its send direction of the
		// stream.
		qinfo("[strm][%p] Peer aborted\n", Stream);
		break;
	case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
		// The peer aborted its send direction of the stream.
		qinfo("[strm][%p] Peer shut down\n", Stream);
		break;
	case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
		// Both directions of the stream have been shut down and MsQuic
		// is done with the stream. It can now be safely cleaned up.
		qinfo("[strm][%p] All done\n", Stream);
		if (!Event->SHUTDOWN_COMPLETE.AppCloseInProgress) {
			MsQuic->StreamClose(Stream);
		}
		break;
	default:
		break;
	}
	return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
    _Function_class_(QUIC_CONNECTION_CALLBACK) QUIC_STATUS QUIC_API
QuicConnectionCallback(_In_ HQUIC Connection, _In_opt_ void *Context,
        _Inout_ QUIC_CONNECTION_EVENT *Event)
{
	nni_proto_pipe_ops *pipe_ops = g_quic_proto->proto_pipe_ops;
	quic_strm_t        *qstrm    = GStream;

	switch (Event->Type) {
	case QUIC_CONNECTION_EVENT_CONNECTED:
		// The handshake has completed for the connection.
		// do not init any var here due to potential frequent reconnect
		qinfo("[conn][%p] Connected\n", Connection);

		// First starting the quic stream
		// if (!qstrm->rticket_active) {
			if (0 != quic_strm_start(Connection, qstrm, &qstrm->stream, qstrm->rticket_active)) {
				qdebug("Error in quic strm start.\n");
				break;
			}
			MsQuic->StreamReceiveSetEnabled(qstrm->stream, FALSE);
		// }

		// Start/ReStart the nng pipe
		if ((qstrm->pipe = nng_alloc(pipe_ops->pipe_size)) == NULL) {
			qdebug("error in alloc pipe.\n");
		}
		pipe_ops->pipe_init(qstrm->pipe, (nni_pipe *)qstrm, Context);
		pipe_ops->pipe_start(qstrm->pipe);
		break;
	case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
		// The connection has been shut down by the transport.
		// Generally, this is the expected way for the connection to
		// shut down with this protocol, since we let idle timeout kill
		// the connection.
		if (Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status ==
		    QUIC_STATUS_CONNECTION_IDLE) {
			qinfo("[conn][%p] Successfully shut down on idle.\n",
			    Connection);
		} else {
			qinfo("[conn][%p] Shut down by transport, 0x%x\n",
			    Connection,
			    Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
		}
		if (qstrm->pipe) {
			pipe_ops->pipe_close(qstrm->pipe);
			pipe_ops->pipe_stop(qstrm->pipe);
		}
		qdebug("pipe stop\n");
		break;
	case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
		// The connection was explicitly shut down by the peer.
		qinfo("[conn][%p] Shut down by peer, 0x%llu\n", Connection,
		    (unsigned long long) Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
		if (qstrm->pipe) {
			pipe_ops->pipe_close(qstrm->pipe);
			pipe_ops->pipe_stop(qstrm->pipe);
		}
		break;
	case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
		// The connection has completed the shutdown process and is
		// ready to be safely cleaned up.
		qinfo("[conn][%p] All done\n\n", Connection);
		if (!Event->SHUTDOWN_COMPLETE.AppCloseInProgress) {
			MsQuic->ConnectionClose(Connection);
		}

		// Close and finite nng pipe ONCE disconnect
		if (qstrm->pipe) {
			pipe_ops->pipe_fini(qstrm->pipe);
		}

		if (qstrm->rticket_active) {
			qinfo("[conn][%p] try to resume by ticket\n", Connection);
			quic_reconnect(qstrm);
		} else { // No rticket
			quic_strm_fini(qstrm);
			nng_free(qstrm, sizeof(quic_strm_t));
		}

		break;
	case QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED:
		// A resumption ticket (also called New Session Ticket or NST)
		// was received from the server.
		qinfo("[conn][%p] Resumption ticket received (%u bytes):\n",
		    Connection, Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength);
		/*
		for (uint32_t i = 0; i <
		     Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength;
		     i++) {
			qdebug("%x",
			    (uint8_t) Event->RESUMPTION_TICKET_RECEIVED
			        .ResumptionTicket[i]);
		}
		qdebug("\n");
		*/
		qstrm->rticket_active = true;
		qstrm->rticket_sz = Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength;
		memcpy(qstrm->rticket, Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicket,
		        Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength);
		break;
	default:
		break;
	}
	return QUIC_STATUS_SUCCESS;
}

static int
quic_strm_close(HQUIC Connection, HQUIC Stream)
{
	if (Stream)
		MsQuic->StreamClose(Stream);
	if (Connection)
		MsQuic->ConnectionShutdown(Connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
}

/**
 * @brief
 *
 * @param Connection
 * @param Context
 * @param Streamp
 * @return int
 */
static int
quic_strm_start(HQUIC Connection, void *Context, HQUIC *Streamp, bool active)
{
	HQUIC       Stream = NULL;
	QUIC_STATUS Status;

	// Create/allocate a new bidirectional stream. The stream is just
	// allocated and no QUIC stream identifier is assigned until it's
	// started.
	if (QUIC_FAILED(Status = MsQuic->StreamOpen(Connection,
	                    QUIC_STREAM_OPEN_FLAG_NONE, QuicStreamCallback, Context, &Stream))) {
		qdebug("StreamOpen failed, 0x%x!\n", Status);
		goto Error;
	}

	qinfo("[strm][%p] Starting...\n", Stream);

	// Starts the bidirectional stream. By default, the peer is not
	// notified of the stream being started until data is sent on the
	// stream.
	if (QUIC_FAILED(Status = MsQuic->StreamStart(
	                    Stream, QUIC_STREAM_START_FLAG_NONE))) {
		qdebug("StreamStart failed, 0x%x!\n", Status);
		MsQuic->StreamClose(Stream);
		goto Error;
	}

	qdebug("[strm][%p] Done...\n", Stream);
	*Streamp = Stream;
	return 0;

Error:

	if (QUIC_FAILED(Status)) {
		MsQuic->ConnectionShutdown(
		    Connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
	}
	return (-1);
}

void
quic_proto_open(nni_proto *proto)
{
	g_quic_proto = proto;
}

static void
quic_close()
{
        
}

void
quic_open()
{
	QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

	if (QUIC_FAILED(Status = MsQuicOpen2(&MsQuic))) {
		qdebug("MsQuicOpen2 failed, 0x%x!\n", Status);
		goto Error;
	}

	// Create a registration for the app's connections.
	if (QUIC_FAILED(Status = MsQuic->RegistrationOpen(
	                    &RegConfig, &Registration))) {
		qdebug("RegistrationOpen failed, 0x%x!\n", Status);
		goto Error;
	}

	qdebug("msquic is init.\n");

	return;

Error:

	if (MsQuic != NULL) {
		if (Configuration != NULL) {
			MsQuic->ConfigurationClose(Configuration);
		}
		if (Registration != NULL) {
			// This will block until all outstanding child objects
			// have been closed.
			MsQuic->RegistrationClose(Registration);
		}
		MsQuicClose(MsQuic);
	}
}

int
quic_connect(const char *url, nni_sock *sock)
{
	// Load the client configuration based on the "unsecure" command line
	// option.
	if (!LoadConfiguration(TRUE)) {
		return (-1);
	}

	QUIC_STATUS  Status;
	HQUIC        Connection = NULL;
	quic_strm_t *qstrm = NULL;

	nng_url *url_s;

	void *sock_data = nni_sock_proto_data(sock);
	// Allocate a new connection object.
	if (QUIC_FAILED(Status = MsQuic->ConnectionOpen(Registration,
	                    QuicConnectionCallback, sock_data, &Connection))) {
		qdebug("ConnectionOpen failed, 0x%x!\n", Status);
		goto Error;
	}
	QUIC_ADDR Address = { 0 };
	// Address.Ip.sa_family = QUIC_ADDRESS_FAMILY_UNSPEC;
	Address.Ip.sa_family = QUIC_ADDRESS_FAMILY_INET;
	// Address.Ipv4 = 
	Address.Ipv4.sin_port = htons(0);
	// QuicAddrSetFamily(&Address, QUIC_ADDRESS_FAMILY_UNSPEC);
	// QuicAddrSetPort(&Address, 0);
	if (QUIC_FAILED(Status = MsQuic->SetParam(Connection, QUIC_PARAM_CONN_LOCAL_ADDRESS,
	    sizeof(QUIC_ADDR), &Address))) {
		qdebug("address setting failed, 0x%x!\n", Status);
		goto Error;
	}

	nng_url_parse(&url_s, url);
	for (int i = 0; i < strlen(url_s->u_host); ++i)
		if (url_s->u_host[i] == ':') {
			url_s->u_host[i] = '\0';
			break;
		}

	// Create a pipe for quic client
	if ((qstrm = nng_alloc(sizeof(quic_strm_t))) == NULL) {
		qdebug("Error in alloc quic strm.\n");
		goto Error;
	}
	quic_strm_init(qstrm);

	qstrm->url_s = url_s;
	qstrm->sock = sock;
	GStream = qstrm; // It should be stored in sock, but...

	qinfo("[conn] Connecting... %s : %s\n", url_s->u_host, url_s->u_port);

	// Start the connection to the server.
	if (QUIC_FAILED(Status = MsQuic->ConnectionStart(Connection,
	                    Configuration, QUIC_ADDRESS_FAMILY_UNSPEC,
	                    url_s->u_host, atoi(url_s->u_port)))) {
		qdebug("ConnectionStart failed, 0x%x!\n", Status);
		goto Error;
	}

Error:

	if (QUIC_FAILED(Status) && Connection != NULL) {
		MsQuic->ConnectionClose(Connection);
	}

	return 0;
}

static int
quic_reconnect(quic_strm_t *qstrm)
{
	// Load the client configuration based on the "unsecure" command line
	// option.
	if (!LoadConfiguration(TRUE)) {
		return (-1);
	}

	QUIC_STATUS Status;
	HQUIC       Connection             = NULL;
	void  *sock_data = nni_sock_proto_data(qstrm->sock);
	nng_url *url_s = qstrm->url_s;

	// Allocate a new connection object.
	if (QUIC_FAILED(Status = MsQuic->ConnectionOpen(Registration,
	                    QuicConnectionCallback, sock_data, &Connection))) {
		qdebug("ConnectionOpen failed, 0x%x!\n", Status);
		goto Error;
	}

	if (qstrm->rticket_sz != 0) {
		if (QUIC_FAILED(Status = MsQuic->SetParam(Connection,
		                    QUIC_PARAM_CONN_RESUMPTION_TICKET,
		                    qstrm->rticket_sz, qstrm->rticket))) {
			qdebug("SetParam(QUIC_PARAM_CONN_RESUMPTION_TICKET) "
			       "failed, 0x%x!\n",
			    Status);
			goto Error;
		}
	}

	qinfo("[conn] ReConnecting... %s : %s\n", url_s->u_host, url_s->u_port);

	// Start the connection to the server.
	if (QUIC_FAILED(Status = MsQuic->ConnectionStart(Connection,
	                    Configuration, QUIC_ADDRESS_FAMILY_UNSPEC,
	                    url_s->u_host, atoi(url_s->u_port)))) {
		qdebug("ConnectionStart failed, 0x%x!\n", Status);
		goto Error;
	}

Error:

	if (QUIC_FAILED(Status) && Connection != NULL) {
		MsQuic->ConnectionClose(Connection);
	}

	return 0;
}

static void
quic_strm_send_start(quic_strm_t *qstrm)
{
	nni_aio    *aio;
	nni_msg    *msg;
	QUIC_STATUS Status;

	if (qstrm->closed) {
		while ((aio = nni_list_first(&qstrm->sendq)) != NULL) {
			nni_list_remove(&qstrm->sendq, aio);
			nni_aio_finish_error(aio, NNG_ECLOSED);
		}
		return;
	}

	if ((aio = nni_list_first(&qstrm->sendq)) == NULL) {
		return;
	}

	// This runs to send the message.
	msg = nni_aio_get_msg(aio);

	QUIC_BUFFER *buf=(QUIC_BUFFER*)malloc(sizeof(QUIC_BUFFER)*2);
	int          hl   = nni_msg_header_len(msg);
	int          bl   = nni_msg_len(msg);

	if (hl > 0) {
		QUIC_BUFFER *buf1 = &buf[0];
		buf1->Length = hl;
		buf1->Buffer = nni_msg_header(msg);
	}

	if (bl > 0) {
		QUIC_BUFFER *buf2 = &buf[1];
		buf2->Length = bl;
		buf2->Buffer = nni_msg_body(msg);
	}

	uint8_t type = (((uint8_t *)nni_msg_header(msg))[0] & 0xf0) >> 4;
	qdebug("type is 0x%x %x.\n", type, ((uint8_t *)nni_msg_header(msg))[0]);
	if (type == 1) {
		qdebug("clientid is %s.\n", nng_mqtt_msg_get_connect_client_id(msg));
	}

	if (!buf)
		qdebug("error in iov.\n");
	qdebug(" body len: %d header len: %d \n", buf[1].Length, buf[0].Length);

	if (QUIC_FAILED(Status = MsQuic->StreamSend(qstrm->stream, buf, bl > 0 ? 2:1,
	                    QUIC_SEND_FLAG_NONE, buf))) {
		qdebug("StreamSend failed, 0x%x!\n", Status);
		free(buf);
	}
}

static void
quic_strm_send_cancel(nni_aio *aio, void *arg, int rv)
{
	quic_strm_t *qstrm = arg;

	nni_mtx_lock(&qstrm->mtx);
	if (!nni_aio_list_active(aio)) {
		nni_mtx_unlock(&qstrm->mtx);
		return;
	}
	// If this is being sent, then cancel the pending transfer.
	// The callback on the txaio will cause the user aio to
	// be canceled too.
	if (nni_list_first(&qstrm->sendq) == aio) {
		nni_aio_abort(qstrm->txaio, rv);
		nni_mtx_unlock(&qstrm->mtx);
		return;
	}
	nni_aio_list_remove(aio);
	nni_mtx_unlock(&qstrm->mtx);

	nni_aio_finish_error(aio, rv);
}

static void
quic_strm_recv_start(void *arg)
{
	qdebug("quic_strm_recv_start.\n");
	quic_strm_t *qstrm = arg;

	// TODO recv_start can be called from sender
	if (qstrm->closed) {
		nni_aio *aio;
		while ((aio = nni_list_first(&qstrm->recvq)) != NULL) {
			nni_list_remove(&qstrm->recvq, aio);
			nni_aio_finish_error(aio, NNG_ECLOSED);
		}
		return;
	}
	if (nni_list_empty(&qstrm->recvq)) {
		return;
	}

	MsQuic->StreamReceiveSetEnabled(qstrm->stream, TRUE);
}

static void
mqtt_quic_strm_recv_cancel(nni_aio *aio, void *arg, int rv)
{
	quic_strm_t *p = arg;

	nni_mtx_lock(&p->mtx);
	if (!nni_aio_list_active(aio)) {
		nni_mtx_unlock(&p->mtx);
		return;
	}
	nni_aio_list_remove(aio);
	nni_mtx_unlock(&p->mtx);
	nni_aio_finish_error(aio, rv);
}

int
quic_strm_recv(void *arg, nni_aio *raio)
{
	quic_strm_t *qstrm = arg;
	int                rv;

	if (nni_aio_begin(raio) != 0) {
		return;
	}
	nni_mtx_lock(&qstrm->mtx);
	if ((rv = nni_aio_schedule(raio, mqtt_quic_strm_recv_cancel, qstrm)) !=
	    0) {
		nni_aio_finish_error(raio, rv);
		return;
	}

	nni_list_append(&qstrm->recvq, raio);
	if (nni_list_first(&qstrm->recvq) == raio) {
		//TODO set different init length for different packet.
		qstrm->rxlen = 0;
		qstrm->rwlen = 2; // Minimal RX length
		quic_strm_recv_start(qstrm);
	}
	nni_mtx_unlock(&qstrm->mtx);
	return 0;
}

int
quic_strm_send(void *arg, nni_aio *aio)
{
	int          rv;
	quic_strm_t *qstrm = arg;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&qstrm->mtx);
	/*
	qstrm->txaio = aio;
	if ((rv = nni_aio_schedule(aio, quic_strm_send_cancel, qstrm)) != 0) {
	        nni_mtx_unlock(&qstrm->mtx);
	        nni_aio_finish_error(aio, rv);
	        return (-1);
	}
	*/
	nni_list_append(&qstrm->sendq, aio);
	if (nni_list_first(&qstrm->sendq) == aio) {
		quic_strm_send_start(qstrm);
	}
	nni_mtx_unlock(&qstrm->mtx);

	return 0;
}

// unite init of msquic here, deal with cb of stream
static int
quic_alloc()
{
	return 0;
}

int
nni_msquic_dialer_alloc(nng_stream_dialer **dp, const nng_url *url)
{
	return 0;
}

int
nni_msquic_listener_alloc(nng_stream_listener **lp, const nng_url *url)
{
	return 0;
}
