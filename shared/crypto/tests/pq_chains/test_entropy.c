/* Parent red-team regression: nested entropy callbacks, failure isolation and
 * native concurrent calls. WASM executes the nested/failure cases in Node;
 * the native target additionally runs two pthreads with distinct entropy tapes. */
#include "vector_io.h"
#include "qgp_tidecoin_falcon.h"
#ifdef PQ_NATIVE_THREADS
#include <pthread.h>
#endif
typedef struct {const blob *b;size_t used;unsigned calls,fail;} tape;
static int tape_rng(void *ctx,uint8_t *out,size_t n) {
    tape *t=ctx;t->calls++;
    if((t->fail&&t->calls==t->fail)||n>t->b->n-t->used)return -1;
    memcpy(out,t->b->p+t->used,n);t->used+=n;return 0;
}
typedef struct {tape outer;const vector *inner;unsigned triggered,fail;int ok;} nested;
static int nested_rng(void *ctx,uint8_t *out,size_t n) {
    nested *t=ctx;
    if(!t->triggered++) {
        const blob *f=t->inner->f;uint8_t sig[688];memset(sig,0xA5,sizeof sig);size_t length=99;
        tape inner={&f[RANDOM],0,0,t->fail};
        int r=qgp_tidecoin_falcon_sign(sig,sizeof sig,&length,f[MESSAGE].p,f[MESSAGE].n,f[SK].p,f[SK].n,tape_rng,&inner);
        if(t->fail) {
            t->ok=r!=0&&length==0&&inner.calls==t->fail;
            for(size_t i=0;i<sizeof sig;i++)t->ok&=sig[i]==0xA5;
        } else t->ok=r==0&&length==f[SIGNATURE].n&&memcmp(sig,f[SIGNATURE].p,length)==0&&inner.used==inner.b->n;
    }
    return tape_rng(&t->outer,out,n);
}
#ifdef PQ_NATIVE_THREADS
typedef struct {const vector *v;int ok;} job;
static void *worker(void *opaque) {
    job *j=opaque;const blob *f=j->v->f;j->ok=1;
    /* No CHECK inside workers: the test counter itself is not shared safely. */
    for(unsigned i=0;i<32&&j->ok;i++) {
        tape t={&f[RANDOM],0,0,0};uint8_t sig[688];size_t n=99;
        int r=qgp_tidecoin_falcon_sign(sig,sizeof sig,&n,f[MESSAGE].p,f[MESSAGE].n,f[SK].p,f[SK].n,tape_rng,&t);
        j->ok=r==0&&n==f[SIGNATURE].n&&memcmp(sig,f[SIGNATURE].p,n)==0&&t.used==t.b->n;
        if(j->ok)j->ok=qgp_tidecoin_falcon_verify(sig,n,f[MESSAGE].p,f[MESSAGE].n,f[PK].p,f[PK].n)==0;
    }
    return NULL;
}
#endif
int main(int argc,char **argv) {
    CHECK(argc==2);FILE *in=fopen(argv[1],"rb");CHECK(in);char magic[8];CHECK(fread(magic,1,8,in)==8&&memcmp(magic,"PQPORT01",8)==0);CHECK(read32(in)>=2);
    vector a,b;read_vector(in,&a);read_vector(in,&b);CHECK(fclose(in)==0);CHECK((a.flags&SIGN)&&(b.flags&SIGN));
    for(unsigned fail=0;fail<=2;fail++) {
        nested state={{&a.f[RANDOM],0,0,0},&b,0,fail,0};uint8_t sig[688];size_t n;
        CHECK(qgp_tidecoin_falcon_sign(sig,sizeof sig,&n,a.f[MESSAGE].p,a.f[MESSAGE].n,a.f[SK].p,a.f[SK].n,nested_rng,&state)==0);
        CHECK(n==a.f[SIGNATURE].n&&memcmp(sig,a.f[SIGNATURE].p,n)==0);
        CHECK(state.ok&&state.triggered>=2&&state.outer.used==state.outer.b->n);
    }
    unsigned threads=0;
#ifdef PQ_NATIVE_THREADS
    pthread_t handles[2];job jobs[2]={{&a,0},{&b,0}};
    for(unsigned i=0;i<2;i++)CHECK(pthread_create(&handles[i],NULL,worker,&jobs[i])==0);
    for(unsigned i=0;i<2;i++){CHECK(pthread_join(handles[i],NULL)==0);CHECK(jobs[i].ok);}threads=2;
#endif
    free_vector(&a);free_vector(&b);printf("PASS nested entropy and failure isolation; native_threads=%u checks=%lu\n",threads,checks);return 0;
}
