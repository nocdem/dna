/* Independent facade tests; fixtures come from pinned upstream/NIST, not ports.
 * Compile flags and remaining coverage limits are documented in README.md.
 * CHECK is active under NDEBUG. Any missing/truncated fixture or empty suite fails. */
#include "vector_io.h"
#include "qgp_algorand_falcon.h"
#include "qgp_tidecoin_falcon.h"
#include "qgp_slhdsa.h"
#include "qgp_ckb_sphincs.h"
#include "qgp_mldsa.h"
#include "mutation_cases.h"

static unsigned counts[8], key_counts[8], sign_counts[8], rejected[8];
unsigned long test_existing_dsa(const vector *v);
unsigned long test_boundaries(void);
static unsigned differential_cases;
typedef struct { const uint8_t *p; size_t n, used; unsigned calls, fail_at; } tape;
static int tape_rng(void *opaque, uint8_t *out, size_t n) {
    tape *t = opaque; t->calls++;
    if ((t->fail_at && t->calls >= t->fail_at) || n > t->n - t->used) return -1;
    memcpy(out, t->p + t->used, n); t->used += n; return 0;
}
static void same(const void *a, const blob *b, size_t n) {
    CHECK(n == b->n);
    if(memcmp(a,b->p,n)!=0) {
        size_t i=0;const uint8_t *got=a;while(i<n&&got[i]==b->p[i])i++;
        fprintf(stderr,"Fixture byte mismatch: size=%zu offset=%zu got=%02x expected=%02x\n",n,i,got[i],b->p[i]);
        CHECK(0);
    }
}
static void unchanged(const uint8_t *p, size_t n) {
    for (size_t i=0; i<n; i++) CHECK(p[i] == 0xA5);
}

static void algorand(const vector *v) {
    const blob *f = v->f;
    uint8_t pk[1793], sk[2305], sig[1424], ct[1539]; size_t n = 99;
    CHECK(QGP_ALGORAND_FALCON_PUBLIC_KEY_SIZE == sizeof pk);
    CHECK(QGP_ALGORAND_FALCON_SECRET_KEY_SIZE == sizeof sk);
    CHECK(QGP_ALGORAND_FALCON_SIGNATURE_MAX_SIZE == sizeof sig - 1);
    CHECK(QGP_ALGORAND_FALCON_SIGNATURE_CT_SIZE == sizeof ct - 1);
    CHECK(qgp_algorand_falcon_keypair_from_seed(pk,sizeof pk,sk,sizeof sk,f[SEED].p,f[SEED].n)==0);
    same(pk,&f[PK],sizeof pk); same(sk,&f[SK],sizeof sk); key_counts[1]++;
    memset(sig,0xA5,sizeof sig);
    CHECK(qgp_algorand_falcon_sign(sig,sizeof sig-1,&n,f[MESSAGE].p,f[MESSAGE].n,sk,sizeof sk)==0);
    same(sig,&f[SIGNATURE],n); CHECK(sig[sizeof sig-1]==0xA5); sign_counts[1]++;
    CHECK(sig[0]==0xBA && sig[1]==0);
    CHECK(qgp_algorand_falcon_verify(f[SIGNATURE].p,f[SIGNATURE].n,f[MESSAGE].p,f[MESSAGE].n,pk,sizeof pk)==0);
    CHECK(qgp_algorand_falcon_to_ct(ct,sizeof ct-1,sig,n)==0);
    same(ct,&f[AUX],sizeof ct-1); CHECK(ct[0]==0xDA && ct[1]==0);
    CHECK(qgp_algorand_falcon_verify_ct(ct,sizeof ct-1,f[MESSAGE].p,f[MESSAGE].n,pk,sizeof pk)==0);
    sig[0]=0x3A; CHECK(qgp_algorand_falcon_verify(sig,n,f[MESSAGE].p,f[MESSAGE].n,pk,sizeof pk)!=0); sig[0]=0xBA;
    sig[n-1]^=1; CHECK(qgp_algorand_falcon_verify(sig,n,f[MESSAGE].p,f[MESSAGE].n,pk,sizeof pk)!=0); sig[n-1]^=1;
    sig[n]=0; CHECK(qgp_algorand_falcon_verify(sig,n+1,f[MESSAGE].p,f[MESSAGE].n,pk,sizeof pk)!=0);
    CHECK(qgp_algorand_falcon_verify(sig,n-1,f[MESSAGE].p,f[MESSAGE].n,pk,sizeof pk)!=0);
    CHECK(qgp_algorand_falcon_verify(sig,0,f[MESSAGE].p,f[MESSAGE].n,pk,sizeof pk)!=0);
    ct[0]=0x5A; CHECK(qgp_algorand_falcon_verify_ct(ct,sizeof ct-1,f[MESSAGE].p,f[MESSAGE].n,pk,sizeof pk)!=0); ct[0]=0xDA;
    CHECK(qgp_algorand_falcon_verify_ct(ct,sizeof ct-2,f[MESSAGE].p,f[MESSAGE].n,pk,sizeof pk)!=0);
    if (v->id == 0) {
        CHECK(qgp_algorand_falcon_sign(sig,sizeof sig-1,&n,NULL,0,sk,sizeof sk)==0); same(sig,&f[SIGNATURE],n);
        CHECK(qgp_algorand_falcon_verify(sig,n,NULL,0,pk,sizeof pk)==0);
        memset(sig,0xA5,sizeof sig); n=123;
        CHECK(qgp_algorand_falcon_sign(sig,sizeof sig-2,&n,NULL,0,sk,sizeof sk)!=0);
        CHECK(n==0); unchanged(sig,sizeof sig);
        CHECK(qgp_algorand_falcon_sign(sig,sizeof sig-1,&n,NULL,1,sk,sizeof sk)!=0); CHECK(n==0);
        CHECK(qgp_algorand_falcon_verify(NULL,100,NULL,0,pk,sizeof pk)!=0);
        CHECK(qgp_algorand_falcon_verify(f[SIGNATURE].p,f[SIGNATURE].n,NULL,0,pk,sizeof pk-1)!=0);
        sk[0]^=1; CHECK(qgp_algorand_falcon_sign(sig,sizeof sig-1,&n,NULL,0,sk,sizeof sk)!=0);
        CHECK(n==0); unchanged(sig,sizeof sig);
    }
}

static void tidecoin(const vector *v) {
    const blob *f=v->f; uint8_t pk[897],sk[1281],sig[1024];size_t n=99;
    CHECK(f[PK].n==sizeof pk);
    if(v->id!=1000) CHECK(f[SK].n==sizeof sk);
    if (v->flags & KEYGEN) {
        CHECK(qgp_tidecoin_falcon_keypair_from_seed(pk,sizeof pk,sk,sizeof sk,f[SEED].p,f[SEED].n)==0);
        same(pk,&f[PK],sizeof pk);same(sk,&f[SK],sizeof sk);key_counts[2]++;
    }
    if(v->flags & SIGN) {
        tape t={f[RANDOM].p,f[RANDOM].n,0,0,0};memset(sig,0xA5,sizeof sig);
        CHECK(qgp_tidecoin_falcon_sign(sig,688,&n,f[MESSAGE].p,f[MESSAGE].n,f[SK].p,f[SK].n,tape_rng,&t)==0);
        same(sig,&f[SIGNATURE],n); CHECK(t.used==t.n); unchanged(sig+688,sizeof sig-688);sign_counts[2]++;
    }
    int good=qgp_tidecoin_falcon_verify(f[SIGNATURE].p,f[SIGNATURE].n,f[MESSAGE].p,f[MESSAGE].n,f[PK].p,f[PK].n)==0;
    CHECK(good==!!(v->flags&VALID));if(!good){rejected[2]++;return;}
    if(v->id==1000) return; /* Synthetic norm boundary has no secret key. */
    CHECK(f[SIGNATURE].n<sizeof sig);memcpy(sig,f[SIGNATURE].p,f[SIGNATURE].n);n=f[SIGNATURE].n;
    sig[0]^=0x80; CHECK(qgp_tidecoin_falcon_verify(sig,n,f[MESSAGE].p,f[MESSAGE].n,f[PK].p,f[PK].n)!=0);sig[0]^=0x80;
    sig[n-1]^=1;CHECK(qgp_tidecoin_falcon_verify(sig,n,f[MESSAGE].p,f[MESSAGE].n,f[PK].p,f[PK].n)!=0);sig[n-1]^=1;
    sig[n]=0;CHECK(qgp_tidecoin_falcon_verify(sig,n+1,f[MESSAGE].p,f[MESSAGE].n,f[PK].p,f[PK].n)!=0);
    CHECK(qgp_tidecoin_falcon_verify(sig,n-1,f[MESSAGE].p,f[MESSAGE].n,f[PK].p,f[PK].n)!=0);
    if(v->id==0) {
        for(unsigned fail=1;fail<=2;fail++) {
            tape t={f[RANDOM].p,f[RANDOM].n,0,0,fail};memset(sig,0xA5,sizeof sig);n=99;
            CHECK(qgp_tidecoin_falcon_sign(sig,688,&n,f[MESSAGE].p,f[MESSAGE].n,f[SK].p,f[SK].n,tape_rng,&t)!=0);
            CHECK(n==0 && t.calls==fail);unchanged(sig,sizeof sig);
        }
        tape t={f[RANDOM].p,f[RANDOM].n,0,0,0};
        CHECK(qgp_tidecoin_falcon_sign(sig,687,&n,NULL,0,f[SK].p,f[SK].n,tape_rng,&t)!=0);CHECK(n==0&&t.calls==0);
        CHECK(qgp_tidecoin_falcon_sign(sig,688,&n,NULL,1,f[SK].p,f[SK].n,tape_rng,&t)!=0);CHECK(n==0&&t.calls==0);
        CHECK(qgp_tidecoin_falcon_verify(NULL,0,NULL,0,f[PK].p,f[PK].n)!=0);
        CHECK(qgp_tidecoin_falcon_keypair_from_seed(pk,sizeof pk,sk,sizeof sk,f[SEED].p,47)!=0);
    }
}

static void slhdsa(const vector *v) {
    const blob *f=v->f;qgp_slhdsa_params p;
    CHECK(qgp_slhdsa_get_params((int)v->param,&p)==0);
    CHECK(f[PK].n==p.public_key_bytes);
    int good=qgp_slhdsa_verify_internal((int)v->param,f[SIGNATURE].p,f[SIGNATURE].n,f[MESSAGE].p,f[MESSAGE].n,f[PK].p,f[PK].n)==0;
    CHECK(good==!!(v->flags&VALID));if(!good)rejected[3]++;
    if(v->flags&EXTERNAL) {
        int ext=qgp_slhdsa_verify((int)v->param,f[SIGNATURE].p,f[SIGNATURE].n,f[AUX].p,f[AUX].n,f[CONTEXT].p,f[CONTEXT].n,f[PK].p,f[PK].n)==0;
        CHECK(ext==good);
    }
    if(v->flags&KEYGEN) {
        uint8_t pk[64],sk[128];CHECK(p.public_key_bytes<=sizeof pk&&p.secret_key_bytes<=sizeof sk);
        CHECK(qgp_slhdsa_keypair_from_seed((int)v->param,pk,p.public_key_bytes,sk,p.secret_key_bytes,f[SEED].p,f[SEED].n)==0);
        same(pk,&f[PK],p.public_key_bytes);same(sk,&f[SK],p.secret_key_bytes);key_counts[3]++;
    }
    if(v->flags&SIGN) {
        uint8_t *sig=malloc(p.signature_bytes+1);CHECK(sig);memset(sig,0xA5,p.signature_bytes+1);size_t n=99;
        CHECK(qgp_slhdsa_sign_internal((int)v->param,sig,p.signature_bytes,&n,f[MESSAGE].p,f[MESSAGE].n,f[SK].p,f[SK].n,f[RANDOM].p,f[RANDOM].n)==0);
        same(sig,&f[SIGNATURE],n);CHECK(sig[p.signature_bytes]==0xA5);sign_counts[3]++;
        if(v->flags&EXTERNAL) {
            CHECK(qgp_slhdsa_sign((int)v->param,sig,p.signature_bytes,&n,f[AUX].p,f[AUX].n,f[CONTEXT].p,f[CONTEXT].n,f[SK].p,f[SK].n,f[RANDOM].p,f[RANDOM].n)==0);
            same(sig,&f[SIGNATURE],n);
            uint8_t badctx[255]={0};CHECK(f[CONTEXT].n<=255);
            if(f[CONTEXT].n) {
                memcpy(badctx,f[CONTEXT].p,f[CONTEXT].n);badctx[0]^=1;
                CHECK(qgp_slhdsa_verify((int)v->param,sig,n,f[AUX].p,f[AUX].n,badctx,f[CONTEXT].n,f[PK].p,f[PK].n)!=0);
            }
        }
        sig[n-1]^=1;CHECK(qgp_slhdsa_verify_internal((int)v->param,sig,n,f[MESSAGE].p,f[MESSAGE].n,f[PK].p,f[PK].n)!=0);
        CHECK(qgp_slhdsa_verify_internal((int)v->param,f[SIGNATURE].p,n-1,f[MESSAGE].p,f[MESSAGE].n,f[PK].p,f[PK].n)!=0);
        CHECK(qgp_slhdsa_verify_internal((int)v->param,sig,n+1,f[MESSAGE].p,f[MESSAGE].n,f[PK].p,f[PK].n)!=0);
        memset(sig,0xA5,p.signature_bytes+1);n=99;
        CHECK(qgp_slhdsa_sign_internal((int)v->param,sig,p.signature_bytes-1,&n,f[MESSAGE].p,f[MESSAGE].n,f[SK].p,f[SK].n,f[RANDOM].p,f[RANDOM].n)!=0);
        CHECK(n==0);unchanged(sig,p.signature_bytes+1);
        CHECK(qgp_slhdsa_sign_internal((int)v->param,sig,p.signature_bytes,&n,f[MESSAGE].p,f[MESSAGE].n,f[SK].p,f[SK].n,f[RANDOM].p,f[RANDOM].n-1)!=0);
        CHECK(n==0);unchanged(sig,p.signature_bytes+1);
        uint8_t ctx[256]={0};CHECK(qgp_slhdsa_sign((int)v->param,sig,p.signature_bytes,&n,NULL,0,ctx,sizeof ctx,f[SK].p,f[SK].n,f[RANDOM].p,f[RANDOM].n)!=0);
        CHECK(n==0);free(sig);
    }
}

static void ckb(const vector *v) {
    const blob *f=v->f;uint8_t digest[32];int param=qgp_ckb_sphincs_param_from_id((uint8_t)v->param);
    CHECK(param==(int)v->param-48);
    CHECK(qgp_ckb_sphincs_message_hash(digest,sizeof digest,f[MESSAGE].p,f[MESSAGE].n)==0);
    same(digest,&f[AUX],sizeof digest);qgp_slhdsa_params p;CHECK(qgp_slhdsa_get_params(param,&p)==0);
    uint8_t *sig=malloc(p.signature_bytes);CHECK(sig);size_t n=99;
    CHECK(qgp_ckb_sphincs_sign_digest((uint8_t)v->param,sig,p.signature_bytes,&n,digest,sizeof digest,f[SK].p,f[SK].n,f[RANDOM].p,f[RANDOM].n)==0);
    same(sig,&f[SIGNATURE],n);sign_counts[4]++;
    CHECK(qgp_ckb_sphincs_verify_digest((uint8_t)v->param,sig,n,digest,sizeof digest,f[PK].p,f[PK].n)==0);
    CHECK(qgp_slhdsa_verify_internal(param,sig,n,digest,sizeof digest,f[PK].p,f[PK].n)!=0);
    digest[0]^=1;CHECK(qgp_ckb_sphincs_verify_digest((uint8_t)v->param,sig,n,digest,sizeof digest,f[PK].p,f[PK].n)!=0);
    CHECK(qgp_ckb_sphincs_verify_digest((uint8_t)v->param,sig,n,digest,31,f[PK].p,f[PK].n)!=0);
    free(sig);
}

static void mldsa(const vector *v) {
    const blob *f=v->f;qgp_mldsa_params p;CHECK(qgp_mldsa_get_params((int)v->param,&p)==0);
    CHECK(p.seed_bytes==32 && p.random_bytes==32 && f[PK].n==p.public_key_bytes);
    uint8_t pk[1952],sk[4032],sig[3310];size_t n=99;
    CHECK(p.public_key_bytes<=sizeof pk&&p.secret_key_bytes<=sizeof sk&&p.signature_bytes<sizeof sig);
    if(v->flags&KEYGEN) {
        CHECK(qgp_mldsa_keypair_from_seed((int)v->param,pk,p.public_key_bytes,sk,p.secret_key_bytes,f[SEED].p,f[SEED].n)==0);
        same(pk,&f[PK],p.public_key_bytes);same(sk,&f[SK],p.secret_key_bytes);key_counts[5]++;
        CHECK(qgp_mldsa_keypair_from_seed((int)v->param,pk,p.public_key_bytes,sk,p.secret_key_bytes,f[SEED].p,31)!=0);
        return;
    }
    int good=qgp_mldsa_verify_internal((int)v->param,f[SIGNATURE].p,f[SIGNATURE].n,f[MESSAGE].p,f[MESSAGE].n,f[PK].p,f[PK].n)==0;
    CHECK(good==!!(v->flags&VALID));if(!good)rejected[5]++;
    if(v->flags&EXTERNAL) {
        CHECK((qgp_mldsa_verify((int)v->param,f[SIGNATURE].p,f[SIGNATURE].n,f[AUX].p,f[AUX].n,f[CONTEXT].p,f[CONTEXT].n,f[PK].p,f[PK].n)==0)==good);
    }
    if(v->flags&SIGN) {
        memset(sig,0xA5,sizeof sig);
        CHECK(qgp_mldsa_sign_internal((int)v->param,sig,p.signature_bytes,&n,f[MESSAGE].p,f[MESSAGE].n,f[SK].p,f[SK].n,f[RANDOM].p,f[RANDOM].n)==0);
        same(sig,&f[SIGNATURE],n);unchanged(sig+n,sizeof sig-n);sign_counts[5]++;
        if(v->flags&EXTERNAL) {
            CHECK(qgp_mldsa_sign((int)v->param,sig,p.signature_bytes,&n,f[AUX].p,f[AUX].n,f[CONTEXT].p,f[CONTEXT].n,f[SK].p,f[SK].n,f[RANDOM].p,f[RANDOM].n)==0);
            same(sig,&f[SIGNATURE],n);
            uint8_t badctx[256]={0};
            CHECK(qgp_mldsa_verify((int)v->param,sig,n,f[AUX].p,f[AUX].n,badctx,256,f[PK].p,f[PK].n)!=0);
            if(f[CONTEXT].n) {
                memcpy(badctx,f[CONTEXT].p,f[CONTEXT].n);badctx[0]^=1;
                CHECK(qgp_mldsa_verify((int)v->param,sig,n,f[AUX].p,f[AUX].n,badctx,f[CONTEXT].n,f[PK].p,f[PK].n)!=0);
            }
        }
        sig[n-1]^=1;CHECK(qgp_mldsa_verify_internal((int)v->param,sig,n,f[MESSAGE].p,f[MESSAGE].n,f[PK].p,f[PK].n)!=0);
        CHECK(qgp_mldsa_verify_internal((int)v->param,f[SIGNATURE].p,n-1,f[MESSAGE].p,f[MESSAGE].n,f[PK].p,f[PK].n)!=0);
        memset(sig,0xA5,sizeof sig);n=99;
        CHECK(qgp_mldsa_sign_internal((int)v->param,sig,p.signature_bytes-1,&n,f[MESSAGE].p,f[MESSAGE].n,f[SK].p,f[SK].n,f[RANDOM].p,f[RANDOM].n)!=0);CHECK(n==0);unchanged(sig,sizeof sig);
        CHECK(qgp_mldsa_sign_internal((int)v->param,sig,p.signature_bytes,&n,f[MESSAGE].p,f[MESSAGE].n,f[SK].p,f[SK].n,f[RANDOM].p,31)!=0);CHECK(n==0);
    }
}

static void differential(const vector *v) {
    CHECK(v->f[AUX].n==MUTATION_COUNT&&v->f[AUX].p[0]==1);
    for(unsigned i=0;i<MUTATION_COUNT;i++) {
        mutation m=make_mutation(v,i);int r=-1;
        if(v->scheme==1) {
            r=(v->flags&CT)?qgp_algorand_falcon_verify_ct(m.sig.p,m.sig.n,m.msg.p,m.msg.n,m.pk.p,m.pk.n):
                qgp_algorand_falcon_verify(m.sig.p,m.sig.n,m.msg.p,m.msg.n,m.pk.p,m.pk.n);
        } else if(v->scheme==2) r=qgp_tidecoin_falcon_verify(m.sig.p,m.sig.n,m.msg.p,m.msg.n,m.pk.p,m.pk.n);
        else if(v->scheme==3) r=qgp_slhdsa_verify_internal((int)v->param,m.sig.p,m.sig.n,m.msg.p,m.msg.n,m.pk.p,m.pk.n);
        else if(v->scheme==5) r=qgp_mldsa_verify_internal((int)v->param,m.sig.p,m.sig.n,m.msg.p,m.msg.n,m.pk.p,m.pk.n);
        else CHECK(0);
        if((r==0)!=v->f[AUX].p[i])fprintf(stderr,"Differential disagreement: scheme=%u param=%u ct=%u mutation=%u\n",v->scheme,v->param,!!(v->flags&CT),i);
        CHECK((r==0)==v->f[AUX].p[i]);rejected[v->scheme]+=r!=0;differential_cases++;free_mutation(&m);
    }
}

int main(int argc,char **argv) {
    CHECK(argc>=2);checks+=test_boundaries();unsigned files=0;
    for(int a=1;a<argc;a++) {
        FILE *in=fopen(argv[a],"rb");CHECK(in);char magic[8];CHECK(fread(magic,1,8,in)==8);CHECK(memcmp(magic,"PQPORT01",8)==0);
        uint32_t count=read32(in);CHECK(count>0 && count<=10000);
        for(uint32_t i=0;i<count;i++) {
            vector v;read_vector(in,&v);CHECK(v.scheme>0&&v.scheme<8);counts[v.scheme]++;
            if(v.flags&DIFFERENTIAL)differential(&v);
            else if(v.scheme==1)algorand(&v);else if(v.scheme==2)tidecoin(&v);
            else if(v.scheme==3)slhdsa(&v);else if(v.scheme==4)ckb(&v);else if(v.scheme==5)mldsa(&v);
            else if(v.scheme==6) {
                checks+=test_existing_dsa(&v);key_counts[6]+=!!(v.flags&KEYGEN);sign_counts[6]+=!!(v.flags&SIGN);
                rejected[6]+=!(v.flags&(KEYGEN|VALID));
            } else if(v.scheme==7) {
                uint8_t digest[32];CHECK(qgp_ckb_sphincs_message_hash(digest,32,v.f[MESSAGE].p,v.f[MESSAGE].n)==0);
                same(digest,&v.f[AUX],32);
                if(v.f[MESSAGE].n==0){CHECK(qgp_ckb_sphincs_message_hash(digest,32,NULL,0)==0);same(digest,&v.f[AUX],32);}
            } else CHECK(0);
            free_vector(&v);
        }
        CHECK(fgetc(in)==EOF);CHECK(fclose(in)==0);files++;
    }
    for(unsigned id=0;id<256;id++)CHECK(qgp_ckb_sphincs_param_from_id((uint8_t)id)==(id>=48&&id<=59?(int)id-48:-1));
    qgp_slhdsa_params p;CHECK(qgp_slhdsa_get_params(-1,&p)!=0);CHECK(qgp_slhdsa_get_params(12,&p)!=0);
    for(unsigned i=1;i<8;i++)if(counts[i])printf("scheme%u vectors=%u keypairs=%u exact_signatures=%u upstream_rejections=%u\n",i,counts[i],key_counts[i],sign_counts[i],rejected[i]);
    printf("PASS files=%u checks=%lu differential_cases=%u\n",files,checks,differential_cases);return 0;
}
