#include "qgp_slhdsa.h"
#include <stdlib.h>
#include <string.h>
typedef struct {
 int (*seeded)(uint8_t *,uint8_t *,const uint8_t *);
 int (*sign)(uint8_t *,size_t *,const uint8_t *,size_t,const uint8_t *,const uint8_t *);
 int (*verify)(const uint8_t *,size_t,const uint8_t *,size_t,const uint8_t *);
 void (*sizes)(size_t *);
} implementation;
extern int qgp_spx_sha2_128f_seeded(uint8_t *,uint8_t *,const uint8_t *);
extern int qgp_spx_sha2_128f_detached(uint8_t *,size_t *,const uint8_t *,size_t,const uint8_t *,const uint8_t *);
extern int qgp_spx_sha2_128f_check(const uint8_t *,size_t,const uint8_t *,size_t,const uint8_t *);
extern void qgp_spx_sha2_128f_sizes(size_t *);
extern int qgp_spx_sha2_128s_seeded(uint8_t *,uint8_t *,const uint8_t *);
extern int qgp_spx_sha2_128s_detached(uint8_t *,size_t *,const uint8_t *,size_t,const uint8_t *,const uint8_t *);
extern int qgp_spx_sha2_128s_check(const uint8_t *,size_t,const uint8_t *,size_t,const uint8_t *);
extern void qgp_spx_sha2_128s_sizes(size_t *);
extern int qgp_spx_sha2_192f_seeded(uint8_t *,uint8_t *,const uint8_t *);
extern int qgp_spx_sha2_192f_detached(uint8_t *,size_t *,const uint8_t *,size_t,const uint8_t *,const uint8_t *);
extern int qgp_spx_sha2_192f_check(const uint8_t *,size_t,const uint8_t *,size_t,const uint8_t *);
extern void qgp_spx_sha2_192f_sizes(size_t *);
extern int qgp_spx_sha2_192s_seeded(uint8_t *,uint8_t *,const uint8_t *);
extern int qgp_spx_sha2_192s_detached(uint8_t *,size_t *,const uint8_t *,size_t,const uint8_t *,const uint8_t *);
extern int qgp_spx_sha2_192s_check(const uint8_t *,size_t,const uint8_t *,size_t,const uint8_t *);
extern void qgp_spx_sha2_192s_sizes(size_t *);
extern int qgp_spx_sha2_256f_seeded(uint8_t *,uint8_t *,const uint8_t *);
extern int qgp_spx_sha2_256f_detached(uint8_t *,size_t *,const uint8_t *,size_t,const uint8_t *,const uint8_t *);
extern int qgp_spx_sha2_256f_check(const uint8_t *,size_t,const uint8_t *,size_t,const uint8_t *);
extern void qgp_spx_sha2_256f_sizes(size_t *);
extern int qgp_spx_sha2_256s_seeded(uint8_t *,uint8_t *,const uint8_t *);
extern int qgp_spx_sha2_256s_detached(uint8_t *,size_t *,const uint8_t *,size_t,const uint8_t *,const uint8_t *);
extern int qgp_spx_sha2_256s_check(const uint8_t *,size_t,const uint8_t *,size_t,const uint8_t *);
extern void qgp_spx_sha2_256s_sizes(size_t *);
extern int qgp_spx_shake_128f_seeded(uint8_t *,uint8_t *,const uint8_t *);
extern int qgp_spx_shake_128f_detached(uint8_t *,size_t *,const uint8_t *,size_t,const uint8_t *,const uint8_t *);
extern int qgp_spx_shake_128f_check(const uint8_t *,size_t,const uint8_t *,size_t,const uint8_t *);
extern void qgp_spx_shake_128f_sizes(size_t *);
extern int qgp_spx_shake_128s_seeded(uint8_t *,uint8_t *,const uint8_t *);
extern int qgp_spx_shake_128s_detached(uint8_t *,size_t *,const uint8_t *,size_t,const uint8_t *,const uint8_t *);
extern int qgp_spx_shake_128s_check(const uint8_t *,size_t,const uint8_t *,size_t,const uint8_t *);
extern void qgp_spx_shake_128s_sizes(size_t *);
extern int qgp_spx_shake_192f_seeded(uint8_t *,uint8_t *,const uint8_t *);
extern int qgp_spx_shake_192f_detached(uint8_t *,size_t *,const uint8_t *,size_t,const uint8_t *,const uint8_t *);
extern int qgp_spx_shake_192f_check(const uint8_t *,size_t,const uint8_t *,size_t,const uint8_t *);
extern void qgp_spx_shake_192f_sizes(size_t *);
extern int qgp_spx_shake_192s_seeded(uint8_t *,uint8_t *,const uint8_t *);
extern int qgp_spx_shake_192s_detached(uint8_t *,size_t *,const uint8_t *,size_t,const uint8_t *,const uint8_t *);
extern int qgp_spx_shake_192s_check(const uint8_t *,size_t,const uint8_t *,size_t,const uint8_t *);
extern void qgp_spx_shake_192s_sizes(size_t *);
extern int qgp_spx_shake_256f_seeded(uint8_t *,uint8_t *,const uint8_t *);
extern int qgp_spx_shake_256f_detached(uint8_t *,size_t *,const uint8_t *,size_t,const uint8_t *,const uint8_t *);
extern int qgp_spx_shake_256f_check(const uint8_t *,size_t,const uint8_t *,size_t,const uint8_t *);
extern void qgp_spx_shake_256f_sizes(size_t *);
extern int qgp_spx_shake_256s_seeded(uint8_t *,uint8_t *,const uint8_t *);
extern int qgp_spx_shake_256s_detached(uint8_t *,size_t *,const uint8_t *,size_t,const uint8_t *,const uint8_t *);
extern int qgp_spx_shake_256s_check(const uint8_t *,size_t,const uint8_t *,size_t,const uint8_t *);
extern void qgp_spx_shake_256s_sizes(size_t *);
static const implementation variants[] = {
 {qgp_spx_sha2_128f_seeded,qgp_spx_sha2_128f_detached,qgp_spx_sha2_128f_check,qgp_spx_sha2_128f_sizes},
 {qgp_spx_sha2_128s_seeded,qgp_spx_sha2_128s_detached,qgp_spx_sha2_128s_check,qgp_spx_sha2_128s_sizes},
 {qgp_spx_sha2_192f_seeded,qgp_spx_sha2_192f_detached,qgp_spx_sha2_192f_check,qgp_spx_sha2_192f_sizes},
 {qgp_spx_sha2_192s_seeded,qgp_spx_sha2_192s_detached,qgp_spx_sha2_192s_check,qgp_spx_sha2_192s_sizes},
 {qgp_spx_sha2_256f_seeded,qgp_spx_sha2_256f_detached,qgp_spx_sha2_256f_check,qgp_spx_sha2_256f_sizes},
 {qgp_spx_sha2_256s_seeded,qgp_spx_sha2_256s_detached,qgp_spx_sha2_256s_check,qgp_spx_sha2_256s_sizes},
 {qgp_spx_shake_128f_seeded,qgp_spx_shake_128f_detached,qgp_spx_shake_128f_check,qgp_spx_shake_128f_sizes},
 {qgp_spx_shake_128s_seeded,qgp_spx_shake_128s_detached,qgp_spx_shake_128s_check,qgp_spx_shake_128s_sizes},
 {qgp_spx_shake_192f_seeded,qgp_spx_shake_192f_detached,qgp_spx_shake_192f_check,qgp_spx_shake_192f_sizes},
 {qgp_spx_shake_192s_seeded,qgp_spx_shake_192s_detached,qgp_spx_shake_192s_check,qgp_spx_shake_192s_sizes},
 {qgp_spx_shake_256f_seeded,qgp_spx_shake_256f_detached,qgp_spx_shake_256f_check,qgp_spx_shake_256f_sizes},
 {qgp_spx_shake_256s_seeded,qgp_spx_shake_256s_detached,qgp_spx_shake_256s_check,qgp_spx_shake_256s_sizes}
};
static const uint8_t empty = 0;
static void clear_bytes(void *p,size_t n) {
 volatile uint8_t *v = (volatile uint8_t *)p;
 while(n--) *v++ = 0;
}
int qgp_slhdsa_get_params(int p,qgp_slhdsa_params *out) {
 size_t s[5];
 if(p<0 || p>=12 || !out) return -1;
 variants[p].sizes(s);
 out->public_key_bytes=s[0]; out->secret_key_bytes=s[1];
 out->signature_bytes=s[2]; out->seed_bytes=s[3]; out->optrand_bytes=s[4];
 return 0;
}
int qgp_slhdsa_keypair_from_seed(int p,uint8_t *pk,size_t pl,uint8_t *sk,size_t sl,const uint8_t *seed,size_t seedl) {
 qgp_slhdsa_params s;
 uint8_t *tmp; int r;
 if(qgp_slhdsa_get_params(p,&s) || !pk || !sk || !seed ||
    pl!=s.public_key_bytes || sl!=s.secret_key_bytes || seedl!=s.seed_bytes) return -1;
 tmp=(uint8_t *)malloc(s.public_key_bytes+s.secret_key_bytes);
 if(!tmp) return -1;
 r=variants[p].seeded(tmp,tmp+s.public_key_bytes,seed);
 if(!r) { memcpy(pk,tmp,pl); memcpy(sk,tmp+pl,sl); }
 clear_bytes(tmp,s.public_key_bytes+s.secret_key_bytes); free(tmp);
 return r;
}
int qgp_slhdsa_sign_internal(int p,uint8_t *sig,size_t cap,size_t *len,const uint8_t *m,size_t ml,const uint8_t *sk,size_t sl,const uint8_t *op,size_t ol) {
 qgp_slhdsa_params s; uint8_t *tmp; size_t written=0; int r;
 if(!len) return -1;
 *len=0;
 if(qgp_slhdsa_get_params(p,&s) || !sig || !sk || !op || (!m && ml) ||
    cap<s.signature_bytes || sl!=s.secret_key_bytes || ol!=s.optrand_bytes) return -1;
 tmp=(uint8_t *)malloc(s.signature_bytes);
 if(!tmp) return -1;
 r=variants[p].sign(tmp,&written,m?m:&empty,ml,sk,op);
 if(!r && written==s.signature_bytes) { memcpy(sig,tmp,written); *len=written; }
 else r=-1;
 clear_bytes(tmp,s.signature_bytes); free(tmp); return r;
}
int qgp_slhdsa_verify_internal(int p,const uint8_t *sig,size_t len,const uint8_t *m,size_t ml,const uint8_t *pk,size_t pl) {
 qgp_slhdsa_params s;
 if(qgp_slhdsa_get_params(p,&s) || !sig || !pk || (!m && ml) ||
    len!=s.signature_bytes || pl!=s.public_key_bytes) return -1;
 return variants[p].verify(sig,len,m?m:&empty,ml,pk);
}
static uint8_t *frame(const uint8_t *m,size_t ml,const uint8_t *ctx,size_t cl,size_t *size) {
 uint8_t *b;
 if(cl>255 || (!ctx && cl) || (!m && ml) || ml>SIZE_MAX-2-cl) return NULL;
 *size=ml+cl+2;
 b=(uint8_t *)malloc(*size);
 if(!b) return NULL;
 b[0]=0; b[1]=(uint8_t)cl;
 if(cl) memcpy(b+2,ctx,cl);
 if(ml) memcpy(b+2+cl,m,ml);
 return b;
}
int qgp_slhdsa_sign(int p,uint8_t *sig,size_t cap,size_t *len,const uint8_t *m,size_t ml,const uint8_t *ctx,size_t cl,const uint8_t *sk,size_t sl,const uint8_t *op,size_t ol) {
 uint8_t *b; size_t size; int r;
 if(!len) return -1;
 *len=0;
 b=frame(m,ml,ctx,cl,&size);
 if(!b) return -1;
 r=qgp_slhdsa_sign_internal(p,sig,cap,len,b,size,sk,sl,op,ol);
 clear_bytes(b,size); free(b); return r;
}
int qgp_slhdsa_verify(int p,const uint8_t *sig,size_t len,const uint8_t *m,size_t ml,const uint8_t *ctx,size_t cl,const uint8_t *pk,size_t pl) {
 uint8_t *b; size_t size; int r;
 b=frame(m,ml,ctx,cl,&size);
 if(!b) return -1;
 r=qgp_slhdsa_verify_internal(p,sig,len,b,size,pk,pl);
 clear_bytes(b,size); free(b); return r;
}
