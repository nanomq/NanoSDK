#ifndef NNG_SUPP_QUIC_API_H
#define NNG_SUPP_QUIC_API_H

#include "core/nng_impl.h"
#include "nng/nng.h"

extern int quic_connect(const char *url, nni_sock *sock);
extern void quic_proto_open(nni_proto *proto);
extern void quic_open();

extern int quic_strm_recv(void *arg, nni_aio *raio);
extern int quic_strm_send(void *arg, nni_aio *saio);
extern void quic_strm_close(void *arg);

#endif
