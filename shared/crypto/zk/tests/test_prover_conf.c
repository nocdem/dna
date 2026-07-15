/**
 * @file test_prover_conf.c
 * @brief B1 Stage-2 — pure-C conf prover byte-match vs the REAL Plonky3 proof.
 *
 * Rebuilds the oracle instance (same outputs/fee/height, same splitmix64 blind
 * derivation, same sandbox tx context string -> conf_txbind map) and the same
 * SmallRng(1) draw stream (tools/vectors/smallrng_goldilocks.json — first-256
 * cross-checked against the S2 KAT), runs dnac_conf_prover_prove, and
 * byte-matches against tools/vectors/conf_root_air_zk{,_h16}.json:
 *
 *   T1  the 17 C-derived publics == the vector's public_values
 *       (root / c_claimed / c_fee from the BUILT trace + tx_binding map)
 *   T2  prove == OK (includes the built-in self-verify: priming zeta
 *       cross-check + dnac_fri_verify + N-chunk constraint check)
 *   T3  zeta + zeta_next == the REAL proof's challenges
 *   T4  trace/quotient/random roots == the REAL proof's commitments
 *   T5  final_poly == the REAL proof's final_poly
 *   T6  fail-close: wrong draw count -> PARAM; non-canonical tx_binding ->
 *       NONCANONICAL
 *
 * Instance is selected by the vector's degree_bits (4 -> h=8 full;
 * 5 -> h=16 padded, 3 FRI rounds).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "conf_txbind.h"
#include "field_goldilocks.h"
#include "stark_prover_conf.h"

/* ===== JSON scanner (test-local convention) ===== */
typedef struct { const char *src; size_t pos; size_t len; } js_t;
static void js_skip_ws(js_t *s){ while(s->pos<s->len){ char c=s->src[s->pos]; if(c==' '||c=='\t'||c=='\n'||c=='\r')s->pos++; else return; } }
static int  js_peek(js_t *s,char c){ js_skip_ws(s); return s->pos<s->len && s->src[s->pos]==c; }
static int  js_match(js_t *s,char c){ js_skip_ws(s); if(s->pos<s->len&&s->src[s->pos]==c){s->pos++;return 1;} return 0; }
static char *js_read_string(js_t *s){
    js_skip_ws(s); if(s->pos>=s->len||s->src[s->pos]!='"')return NULL; s->pos++;
    size_t start=s->pos; while(s->pos<s->len&&s->src[s->pos]!='"')s->pos++;
    if(s->pos>=s->len){ return NULL; }
    size_t n=s->pos-start; s->pos++;
    char *o=(char*)malloc(n+1); if(!o)return NULL; memcpy(o,s->src+start,n); o[n]='\0'; return o;
}
static int js_read_u64(js_t *s,uint64_t *out){
    js_skip_ws(s); if(s->pos>=s->len)return 0; char *e=NULL;
    unsigned long long v=strtoull(s->src+s->pos,&e,10); if(e==s->src+s->pos)return 0;
    s->pos=(size_t)(e-s->src); *out=(uint64_t)v; return 1;
}
static int js_skip_value(js_t *s);
static int js_skip_object(js_t *s){ if(!js_match(s,'{'))return 0; while(1){ if(js_match(s,'}'))return 1; if(js_peek(s,',')){s->pos++;continue;} char*k=js_read_string(s); if(!k)return 0; free(k); if(!js_match(s,':'))return 0; if(!js_skip_value(s))return 0; } }
static int js_skip_array(js_t *s){ if(!js_match(s,'['))return 0; while(1){ if(js_match(s,']'))return 1; if(js_peek(s,',')){s->pos++;continue;} if(!js_skip_value(s))return 0; } }
static int js_skip_value(js_t *s){
    js_skip_ws(s); if(s->pos>=s->len)return 0; char c=s->src[s->pos];
    if(c=='{'){ return js_skip_object(s); }
    if(c=='['){ return js_skip_array(s); }
    if(c=='"'){char*t=js_read_string(s); if(!t)return 0; free(t); return 1;}
    if(c=='t'){s->pos+=4;return 1;} if(c=='f'){s->pos+=5;return 1;} if(c=='n'){s->pos+=4;return 1;}
    while(s->pos<s->len){ char d=s->src[s->pos]; if((d>='0'&&d<='9')||d=='-'||d=='+'||d=='.'||d=='e'||d=='E')s->pos++; else break; }
    return 1;
}
static char *slurp(const char *path,size_t *out_len){
    FILE *fp=fopen(path,"rb"); if(!fp)return NULL; fseek(fp,0,SEEK_END); long sz=ftell(fp); fseek(fp,0,SEEK_SET);
    if(sz<0){fclose(fp);return NULL;} char *b=(char*)malloc((size_t)sz+1); if(!b){fclose(fp);return NULL;}
    size_t got=fread(b,1,(size_t)sz,fp); fclose(fp); b[got]='\0'; *out_len=got; return b;
}
static int hexnib(char c){ if(c>='0'&&c<='9')return c-'0'; if(c>='a'&&c<='f')return c-'a'+10; if(c>='A'&&c<='F')return c-'A'+10; return -1; }
static size_t hex_decode(const char *hex,uint8_t *buf,size_t cap){
    size_t hl=strlen(hex); if(hl%2)return (size_t)-1; size_t n=hl/2; if(n>cap)return (size_t)-1;
    for(size_t i=0;i<n;i++){ int hi=hexnib(hex[2*i]),lo=hexnib(hex[2*i+1]); if(hi<0||lo<0)return (size_t)-1; buf[i]=(uint8_t)((hi<<4)|lo); } return n;
}
static gold_fp2_t parse_fp2_decimal(js_t *s){
    uint64_t c0=0,c1=0; js_match(s,'{');
    while(!js_match(s,'}')){ if(js_peek(s,',')){s->pos++;continue;} char*k=js_read_string(s); js_match(s,':'); char*v=js_peek(s,'"')?js_read_string(s):NULL;
        if(v&&k&&strcmp(k,"c0_decimal")==0)c0=strtoull(v,NULL,10); else if(v&&k&&strcmp(k,"c1_decimal")==0)c1=strtoull(v,NULL,10); else if(!v)js_skip_value(s); free(v); free(k); }
    return gold_fp2_new(gold_fp_from_u64(c0),gold_fp_from_u64(c1));
}
/* serde fp2: {"value":[{"value":c0},{"value":c1}]} */
static uint64_t parse_base_obj(js_t *s){ uint64_t r=0; js_match(s,'{'); while(!js_match(s,'}')){ if(js_peek(s,',')){s->pos++;continue;} char*k=js_read_string(s); js_match(s,':'); if(k&&strcmp(k,"value")==0)js_read_u64(s,&r); else js_skip_value(s); free(k);} return r; }
static gold_fp2_t parse_fp2_wrapped(js_t *s){
    uint64_t comps[2]={0,0}; int n=0; js_match(s,'{');
    while(!js_match(s,'}')){ if(js_peek(s,',')){s->pos++;continue;} char*k=js_read_string(s); js_match(s,':');
        if(k&&strcmp(k,"value")==0){ js_match(s,'['); while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;} uint64_t bv=parse_base_obj(s); if(n<2)comps[n]=bv; n++; } } else { js_skip_value(s); } free(k); }
    return gold_fp2_new(gold_fp_from_u64(comps[0]),gold_fp_from_u64(comps[1]));
}

#define TP_PUB 17
#define TP_FP 16

typedef struct {
    size_t degree_bits;
    gold_fp2_t zeta, zeta_next;
    uint8_t trace_root[64], quot_root[64], rand_root[64];
    uint64_t public_values[TP_PUB]; size_t num_public_values;
    gold_fp2_t final_poly[TP_FP]; size_t num_final_poly;
} tp_t;

static void parse_conf_vector(js_t *s, tp_t *fx){
    js_match(s,'{');
    while(!js_match(s,'}')){ if(js_peek(s,',')){s->pos++;continue;} char*k=js_read_string(s); if(!k)break; js_match(s,':');
        if(strcmp(k,"instance")==0){
            js_match(s,'{'); while(!js_match(s,'}')){ if(js_peek(s,',')){s->pos++;continue;} char*ik=js_read_string(s); js_match(s,':'); uint64_t v=0; js_read_u64(s,&v);
                if(ik&&strcmp(ik,"degree_bits")==0){fx->degree_bits=(size_t)v;}
                free(ik); }
        } else if(strcmp(k,"challenges")==0){
            js_match(s,'{'); while(!js_match(s,'}')){ if(js_peek(s,',')){s->pos++;continue;} char*ck=js_read_string(s); js_match(s,':');
                if(ck&&strcmp(ck,"zeta_fp2")==0)fx->zeta=parse_fp2_decimal(s);
                else if(ck&&strcmp(ck,"zeta_next_fp2")==0)fx->zeta_next=parse_fp2_decimal(s);
                else js_skip_value(s);
                free(ck); }
        } else if(strcmp(k,"commitments")==0){
            js_match(s,'{'); while(!js_match(s,'}')){ if(js_peek(s,',')){s->pos++;continue;} char*ck=js_read_string(s); js_match(s,':');
                if(ck&&strcmp(ck,"trace_commit_root_hex")==0){ char*h=js_read_string(s); hex_decode(h,fx->trace_root,64); free(h); }
                else if(ck&&strcmp(ck,"quotient_commit_root_hex")==0){ char*h=js_read_string(s); hex_decode(h,fx->quot_root,64); free(h); }
                else if(ck&&strcmp(ck,"random_commit_root_hex")==0){ char*h=js_read_string(s); hex_decode(h,fx->rand_root,64); free(h); }
                else js_skip_value(s);
                free(ck); }
        } else if(strcmp(k,"public_values")==0){
            size_t n=0; js_match(s,'['); while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;} char*v=js_read_string(s); if(v&&n<TP_PUB)fx->public_values[n]=strtoull(v,NULL,10); free(v); n++; } fx->num_public_values=n;
        } else if(strcmp(k,"proof_serde")==0){
            /* tuple [rand_cw_openings, inner FriProof]; only final_poly needed */
            js_match(s,'['); js_skip_value(s); if(js_peek(s,',')) s->pos++;
            js_match(s,'{');
            while(!js_match(s,'}')){ if(js_peek(s,',')){s->pos++;continue;} char*pk=js_read_string(s); js_match(s,':');
                if(pk&&strcmp(pk,"final_poly")==0){ size_t n=0; js_match(s,'['); while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;} gold_fp2_t fv=parse_fp2_wrapped(s); if(n<TP_FP)fx->final_poly[n]=fv; n++; } fx->num_final_poly=n; }
                else js_skip_value(s);
                free(pk); }
            while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;} js_skip_value(s);}
        } else js_skip_value(s);
        free(k);
    }
}

/* splitmix64 blind derivation — mirror of the oracle dump_conf_root_air_common
 * (KAT convenience for byte-stable witness blinds; production = OS entropy). */
typedef struct { uint64_t x; } sm_t;
static uint64_t sm_next(sm_t *s){
    s->x += 0x9e3779b97f4a7c15ULL;
    uint64_t z = s->x;
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    z ^= z >> 31;
    return z % GOLDILOCKS_P;
}

int main(int argc,char **argv){
    if(argc<3){ fprintf(stderr,"usage: %s <conf_root_air_zk.json> <smallrng_goldilocks.json>\n",argv[0]); return 2; }
    tp_t *fx=(tp_t*)calloc(1,sizeof *fx); if(!fx)return 2;
    { size_t bl=0; char *blob=slurp(argv[1],&bl); if(!blob){ fprintf(stderr,"cannot read %s\n",argv[1]); return 2; }
      js_t s={blob,0,bl}; parse_conf_vector(&s,fx); free(blob); }

    /* instance selection by degree_bits (matches the oracle dumps) */
    const uint64_t out8[4] = {10,20,30,40};
    const uint64_t out16[10] = {5,10,15,20,25,30,35,40,45,50};
    const uint64_t *outputs; size_t n_out; uint64_t fee; size_t height;
    if(fx->degree_bits==4){ outputs=out8; n_out=4; fee=7; height=8; }
    else if(fx->degree_bits==5){ outputs=out16; n_out=10; fee=3; height=16; }
    else { fprintf(stderr,"unsupported degree_bits %zu\n",fx->degree_bits); return 2; }

    /* draws: first 708*height of the SmallRng(1) stream */
    const size_t need = DNAC_CONF_PROVER_TOTAL_DRAWS(height);
    uint64_t *draws=(uint64_t*)malloc(need*sizeof(uint64_t));
    if(!draws)return 2;
    { size_t bl=0; char *blob=slurp(argv[2],&bl); if(!blob){ fprintf(stderr,"cannot read %s\n",argv[2]); return 2; }
      js_t s={blob,0,bl}; size_t n=0; js_match(&s,'{');
      while(!js_match(&s,'}')){ if(js_peek(&s,',')){s.pos++;continue;} char*k=js_read_string(&s); if(!k)break; js_match(&s,':');
          if(strcmp(k,"draws")==0){ js_match(&s,'['); while(!js_match(&s,']')){ if(js_peek(&s,',')){s.pos++;continue;} char*v=js_read_string(&s); if(v&&n<need)draws[n]=strtoull(v,NULL,10); free(v); n++; } }
          else js_skip_value(&s);
          free(k); }
      free(blob);
      if(n<need){ fprintf(stderr,"draw stream too short: %zu < %zu\n",n,need); return 2; } }

    /* blinds (2 per row) — oracle splitmix mirror, seed 0xB11D5EED00000000 ^ h */
    uint64_t *blind=(uint64_t*)malloc(2*height*sizeof(uint64_t));
    if(!blind)return 2;
    { sm_t sm={0xB11D5EED00000000ULL ^ (uint64_t)height};
      for(size_t i=0;i<2*height;i++)blind[i]=sm_next(&sm); }

    /* tx_binding — sandbox sighash over the oracle's exact ctx string */
    dnac_conf_prover_instance_t inst; memset(&inst,0,sizeof inst);
    { char ctx[96];
      snprintf(ctx,sizeof ctx,"conf-root-demo-v1|h=%zu|n=%zu|fee=%llu",
               height,n_out,(unsigned long long)fee);
      uint8_t sighash[CONF_TXBIND_SIGHASH_LEN];
      conf_txbind_sandbox_sighash((const uint8_t*)ctx,strlen(ctx),sighash);
      if(!conf_txbind_map(sighash,inst.tx_binding)){ fprintf(stderr,"txbind map fail-close\n"); return 2; } }

    inst.outputs=outputs; inst.n_out=n_out; inst.fee=fee;
    inst.blind=blind; inst.height=height;
    inst.draws=draws; inst.num_draws=need;

    int fails=0;
    printf("── conf instance: height=%zu n_out=%zu degree_bits=%zu draws=%zu\n",
           height,n_out,fx->degree_bits,need);

    /* T2 prove (T1 publics checked after, from the produced proof) */
    dnac_conf_prover_proof_t *pf=NULL;
    dnac_prover_status_t st=dnac_conf_prover_prove(&inst,&pf);
    printf("  T2 dnac_conf_prover_prove -> OK (self-verified)       %s\n",
           st==DNAC_PROVER_OK?"PASS":"FAIL");
    if(st!=DNAC_PROVER_OK){ printf("     status=%d\n",(int)st); free(fx); return 1; }

    /* T1 publics == vector public_values */
    {
        size_t np=0; const gold_fp_t *pub=dnac_conf_prover_proof_publics(pf,&np);
        int ok=(np==TP_PUB)&&(fx->num_public_values==TP_PUB);
        for(size_t i=0;ok&&i<TP_PUB;i++)
            if(gold_fp_to_u64(pub[i])!=fx->public_values[i])ok=0;
        printf("  T1 17 publics (root/c_claimed/c_fee/hash/txbind) == vector %s\n",
               ok?"PASS":"FAIL");
        if(!ok)fails++;
    }
    /* T3 zeta/zeta_next */
    {
        gold_fp2_t z,zn; dnac_conf_prover_proof_zeta(pf,&z,&zn);
        int ok=gold_fp2_eq(z,fx->zeta)&&gold_fp2_eq(zn,fx->zeta_next);
        printf("  T3 zeta + zeta_next == REAL proof challenges          %s\n",
               ok?"PASS":"FAIL");
        if(!ok)fails++;
    }
    /* T4 roots */
    {
        uint8_t tr[64],qr[64],rr[64];
        dnac_conf_prover_proof_roots(pf,tr,qr,rr);
        int ok=!memcmp(tr,fx->trace_root,64)&&!memcmp(qr,fx->quot_root,64)&&!memcmp(rr,fx->rand_root,64);
        printf("  T4 trace/quotient/random roots == REAL commitments    %s\n",
               ok?"PASS":"FAIL");
        if(!ok)fails++;
    }
    /* T5 final_poly */
    {
        size_t n=0; const gold_fp2_t *fp=dnac_conf_prover_proof_final_poly(pf,&n);
        int ok=(n==fx->num_final_poly);
        for(size_t i=0;ok&&i<n;i++) if(!gold_fp2_eq(fp[i],fx->final_poly[i]))ok=0;
        printf("  T5 final_poly (%zu fp2) == REAL proof                  %s\n",
               n,ok?"PASS":"FAIL");
        if(!ok)fails++;
    }
    /* T6 fail-close */
    {
        int ok=1;
        dnac_conf_prover_proof_t *bad=NULL;
        dnac_conf_prover_instance_t bi=inst; bi.num_draws=need-1;
        if(dnac_conf_prover_prove(&bi,&bad)!=DNAC_PROVER_ERR_PARAM)ok=0;
        bi=inst; bi.tx_binding[0]=GOLDILOCKS_P; /* non-canonical */
        if(dnac_conf_prover_prove(&bi,&bad)!=DNAC_PROVER_ERR_NONCANONICAL)ok=0;
        printf("  T6 fail-close: draw-count PARAM + txbind NONCANONICAL %s\n",
               ok?"PASS":"FAIL");
        if(!ok)fails++;
    }

    /* T7 — PRODUCTION path (G2): OS-entropy draws instead of the KAT stream.
     * VALUE-INDEPENDENT (no byte-match — the hiding randomness is non-
     * deterministic by design): the proof must still self-verify (FRI +
     * N-chunk constraint check) and re-verify, and publics (which do NOT
     * depend on the draws) must still equal the KAT proof's publics. */
    {
        dnac_conf_prover_instance_t pi=inst; pi.draws=NULL; pi.num_draws=0;
        dnac_conf_prover_proof_t *pp=NULL;
        dnac_prover_status_t ps=dnac_conf_prover_prove_production(&pi,&pp);
        int ok=(ps==DNAC_PROVER_OK)&&pp&&
               (dnac_conf_prover_proof_verify(pp)==DNAC_FRI_OK);
        if(ok){
            size_t np=0; const gold_fp_t *pub=dnac_conf_prover_proof_publics(pp,&np);
            for(size_t i=0;ok&&i<np;i++)
                if(gold_fp_to_u64(pub[i])!=fx->public_values[i])ok=0;
        }
        printf("  T7 production (OS-entropy) prove self-verifies + publics match %s\n",
               ok?"PASS":"FAIL");
        if(!ok)fails++;
        if(pp)dnac_conf_prover_proof_free(pp);
    }

    dnac_conf_prover_proof_free(pf);
    free(draws); free(blind);
    if(fails){ printf("test_prover_conf: FAIL (%d)\n",fails); free(fx); return 1; }
    printf("test_prover_conf: PASS\n");
    printf("  pure-C conf prove (width 614, num_qc=8, 17 publics) byte-matches the\n");
    printf("  REAL Plonky3 is_zk=1 proof (zeta+roots+final_poly) and self-verifies\n");
    printf("  (FRI DNAC_FRI_OK + N-chunk constraint check). Rust-free end-to-end.\n");
    free(fx);
    return 0;
}
