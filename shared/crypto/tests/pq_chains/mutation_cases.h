/* Deterministic public-input mutations shared by independent oracle and runner.
 * Expected acceptance comes only from the pristine reference executable.
 * Every mutation starts from a fresh copy; case 0 is the positive control. */
#ifndef PQ_MUTATION_CASES_H
#define PQ_MUTATION_CASES_H
#include "vector_io.h"
enum { MUTATION_COUNT=96, DIFFERENTIAL=32 };
typedef struct { blob sig,pk,msg; } mutation;
static inline blob clone_blob(const blob *b) {
    blob r={malloc(b->n+1),b->n};CHECK(r.p);memcpy(r.p,b->p,b->n);r.p[b->n]=0;return r;
}
static inline mutation make_mutation(const vector *v,unsigned i) {
    CHECK(i<MUTATION_COUNT);mutation r={clone_blob(&v->f[SIGNATURE]),clone_blob(&v->f[PK]),clone_blob(&v->f[MESSAGE])};
    CHECK(r.sig.n>64 && r.pk.n>16 && r.msg.n>0);
    if(i==0)return r;
    if(i<=8) {
        const size_t lengths[]={0,1,2,3,40,41,r.sig.n/2,r.sig.n-1};r.sig.n=lengths[i-1];
    } else if(i<=10) { r.sig.p[r.sig.n++]=i==9?0:255;
    } else if(i<=58) {
        unsigned j=i-11;size_t position;
        if(j<16) {size_t pos[]={0,1,2,3,r.sig.n/4,r.sig.n/2,r.sig.n-2,r.sig.n-1};position=pos[j/2];}
        else position=((uint32_t)j*UINT32_C(2654435761)+UINT32_C(1013904223))%r.sig.n;
        r.sig.p[position]^=(uint8_t)(1u<<(j%8));
    } else if(i<=66) {
        unsigned j=i-59;size_t pos[]={0,1,r.pk.n/2,r.pk.n-1};r.pk.p[pos[j/2]]^=(uint8_t)(1u<<(j%8));
    } else if(i==67) {r.pk.n=0;
    } else if(i==68) {r.pk.n--;
    } else if(i==69) {r.pk.p[r.pk.n++]=0;
    } else if(i==70) {r.msg.n=0;
    } else if(i==71) {r.msg.n--;
    } else if(i==72) {r.msg.p[r.msg.n++]=0;
    } else if(i<=84) {
        unsigned j=i-73;size_t pos[]={0,r.msg.n/2,r.msg.n-1};r.msg.p[pos[j%3]]^=(uint8_t)(1u<<(j%8));
    } else if(i==85) {memset(r.sig.p,0,r.sig.n);
    } else if(i==86) {memset(r.sig.p,255,r.sig.n);
    } else if(i==87) {memset(r.pk.p,0,r.pk.n);
    } else if(i==88) {memset(r.pk.p,255,r.pk.n);
    } else {
        /* Parser edge bytes, including negative-zero/unary and header values. */
        const uint8_t values[]={0,1,0x30,0x39,0xBA,0xDA,255};
        r.sig.p[(i-89)%3]=values[i-89];
    }
    return r;
}
static inline void free_mutation(mutation *m) {free(m->sig.p);free(m->pk.p);free(m->msg.p);}
#endif
