/**
 * @file test_prover_action.c
 * @brief Dual-mode S1e.4 — pure-C C1 Action prover byte-match vs the REAL
 *        Plonky3 proof (width 813, is_zk=1, num_qc=8, 0 publics).
 *
 * Rebuilds the oracle instance (dump_conf_action_air_zk: INPUT 100 = OUTPUT 70
 * + FEE 30 + dummy-last, log_height=7) and the SmallRng(1) draw stream
 * (tools/vectors/smallrng_goldilocks.json), runs dnac_action_prover_prove, and
 * byte-matches against tools/vectors/conf_action_air_zk.json:
 *
 *   T2  prove == OK (includes self-verify: priming zeta cross-check +
 *       dnac_fri_verify + N-chunk constraint check)
 *   T3  zeta + zeta_next == the REAL proof's challenges
 *   T4  trace/quotient/random roots == the REAL proof's commitments
 *   T5  final_poly == the REAL proof's final_poly
 *   T6  fail-close: wrong draw count -> PARAM
 *   T7  production (OS-entropy) self-verifies (value-independent)
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "field_goldilocks.h"
#include "stark_prover_action.h"

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
static uint64_t parse_base_obj(js_t *s){ uint64_t r=0; js_match(s,'{'); while(!js_match(s,'}')){ if(js_peek(s,',')){s->pos++;continue;} char*k=js_read_string(s); js_match(s,':'); if(k&&strcmp(k,"value")==0)js_read_u64(s,&r); else js_skip_value(s); free(k);} return r; }
static gold_fp2_t parse_fp2_wrapped(js_t *s){
    uint64_t comps[2]={0,0}; int n=0; js_match(s,'{');
    while(!js_match(s,'}')){ if(js_peek(s,',')){s->pos++;continue;} char*k=js_read_string(s); js_match(s,':');
        if(k&&strcmp(k,"value")==0){ js_match(s,'['); while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;} uint64_t bv=parse_base_obj(s); if(n<2)comps[n]=bv; n++; } } else { js_skip_value(s); } free(k); }
    return gold_fp2_new(gold_fp_from_u64(comps[0]),gold_fp_from_u64(comps[1]));
}

#define TP_FP 16

typedef struct {
    size_t degree_bits;
    gold_fp2_t zeta, zeta_next;
    uint8_t trace_root[64], quot_root[64], rand_root[64];
    gold_fp2_t final_poly[TP_FP]; size_t num_final_poly;
} tp_t;

static void parse_vector(js_t *s, tp_t *fx){
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
        } else if(strcmp(k,"proof_serde")==0){
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

int main(int argc,char **argv){
    if(argc<3){ fprintf(stderr,"usage: %s <conf_action_air_zk.json> <smallrng_goldilocks.json>\n",argv[0]); return 2; }
    tp_t *fx=(tp_t*)calloc(1,sizeof *fx); if(!fx)return 2;
    { size_t bl=0; char *blob=slurp(argv[1],&bl); if(!blob){ fprintf(stderr,"cannot read %s\n",argv[1]); return 2; }
      js_t s={blob,0,bl}; parse_vector(&s,fx); free(blob); }

    /* Fixed instance == dump_conf_action_air_zk (log_height 7, H=128, 4 blocks). */
    const unsigned log_height = 7;
    const size_t height = (size_t)1 << log_height;
    const uint64_t value[3] = {100, 70, 30};
    const uint64_t addr[3*4] = {
        0,0,0,0,                       /* INPUT: overridden (derived) */
        0xAA01,0xAA02,0xAA03,0xAA04,   /* OUTPUT */
        0xFEE1,0xFEE2,0xFEE3,0xFEE4    /* FEE */
    };
    const uint64_t rcm[3*2] = {0x11,0x12, 0x21,0x22, 0x31,0x32};
    const uint8_t  roles[3] = {CONF_ACTION_ROLE_INPUT, CONF_ACTION_ROLE_OUTPUT, CONF_ACTION_ROLE_FEE};
    const uint64_t pos[3]   = {5, 0, 0};
    const uint64_t nk[3]    = {0x22222222ULL, 0, 0};
    const uint64_t ak[3]    = {0x11111111ULL, 0, 0};

    /* draws: first 907*height of the SmallRng(1) stream */
    const size_t need = DNAC_ACTION_PROVER_TOTAL_DRAWS(height);
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

    dnac_action_prover_instance_t inst; memset(&inst,0,sizeof inst);
    inst.value=value; inst.addr=addr; inst.rcm=rcm; inst.roles=roles;
    inst.pos=pos; inst.nk=nk; inst.ak=ak; inst.num_notes=3;
    inst.log_height=log_height; inst.draws=draws; inst.num_draws=need;

    int fails=0;
    printf("── action instance: height=%zu num_notes=3 degree_bits=%zu draws=%zu\n",
           height,fx->degree_bits,need);

    /* T2 prove */
    dnac_action_prover_proof_t *pf=NULL;
    dnac_prover_status_t st=dnac_action_prover_prove(&inst,&pf);
    printf("  T2 dnac_action_prover_prove -> OK (self-verified)     %s\n",
           st==DNAC_PROVER_OK?"PASS":"FAIL");
    if(st!=DNAC_PROVER_OK){ printf("     status=%d\n",(int)st); free(fx); free(draws); return 1; }

    /* T3 zeta/zeta_next */
    {
        gold_fp2_t z,zn; dnac_action_prover_proof_zeta(pf,&z,&zn);
        int ok=gold_fp2_eq(z,fx->zeta)&&gold_fp2_eq(zn,fx->zeta_next);
        printf("  T3 zeta + zeta_next == REAL proof challenges          %s\n",
               ok?"PASS":"FAIL");
        if(!ok)fails++;
    }
    /* T4 roots */
    {
        uint8_t tr[64],qr[64],rr[64];
        dnac_action_prover_proof_roots(pf,tr,qr,rr);
        int ok=!memcmp(tr,fx->trace_root,64)&&!memcmp(qr,fx->quot_root,64)&&!memcmp(rr,fx->rand_root,64);
        printf("  T4 trace/quotient/random roots == REAL commitments    %s\n",
               ok?"PASS":"FAIL");
        if(!ok)fails++;
    }
    /* T5 final_poly */
    {
        size_t n=0; const gold_fp2_t *fp=dnac_action_prover_proof_final_poly(pf,&n);
        int ok=(n==fx->num_final_poly);
        for(size_t i=0;ok&&i<n;i++) if(!gold_fp2_eq(fp[i],fx->final_poly[i]))ok=0;
        printf("  T5 final_poly (%zu fp2) == REAL proof                  %s\n",
               n,ok?"PASS":"FAIL");
        if(!ok)fails++;
    }
    /* T6 fail-close */
    {
        int ok=1;
        dnac_action_prover_proof_t *bad=NULL;
        dnac_action_prover_instance_t bi=inst; bi.num_draws=need-1;
        if(dnac_action_prover_prove(&bi,&bad)!=DNAC_PROVER_ERR_PARAM)ok=0;
        printf("  T6 fail-close: wrong draw count -> PARAM              %s\n",
               ok?"PASS":"FAIL");
        if(!ok)fails++;
    }
    /* T7 production (OS-entropy) self-verifies (value-independent) */
    {
        dnac_action_prover_instance_t pi=inst; pi.draws=NULL; pi.num_draws=0;
        dnac_action_prover_proof_t *pp=NULL;
        dnac_prover_status_t ps=dnac_action_prover_prove_production(&pi,&pp);
        int ok=(ps==DNAC_PROVER_OK)&&pp&&
               (dnac_action_prover_proof_verify(pp)==DNAC_FRI_OK);
        printf("  T7 production (OS-entropy) self-verifies              %s\n",
               ok?"PASS":"FAIL");
        if(!ok)fails++;
        if(pp)dnac_action_prover_proof_free(pp);
    }

    /* T8 (S1e.5) — construction-gate cheats FAIL to prove through the real
     * prover: conf_action_air_generate enforces the honest-prover preconditions
     * (balance conservation, range, block budget), so an invalid instance never
     * reaches a proof. (The complementary "tampered proof FAILS verify" half is
     * gated by test_conf_action_verify T7: tampered trace cell -> OOD.) */
    {
        int ok=1;
        dnac_action_prover_proof_t *bad=NULL;
        /* (a) non-conserving balance: INPUT 100 != OUTPUT 60 + FEE 30. */
        const uint64_t v_bad[3]={100,60,30};
        dnac_action_prover_instance_t ci=inst; ci.value=v_bad;
        if(dnac_action_prover_prove(&ci,&bad)!=DNAC_PROVER_ERR_RANGE)ok=0;
        /* (b) value >= 2^52 (range overflow). */
        const uint64_t v_ovf[3]={ (uint64_t)1<<52, ((uint64_t)1<<52)-30, 30 };
        ci=inst; ci.value=v_ovf;
        if(dnac_action_prover_prove(&ci,&bad)!=DNAC_PROVER_ERR_RANGE)ok=0;
        /* (c) too many notes for the height (num_notes+1 > H/K = 4). */
        const uint64_t v4[4]={100,40,30,30};
        const uint64_t a4[4*4]={0,0,0,0, 1,2,3,4, 5,6,7,8, 9,10,11,12};
        const uint64_t r4[4*2]={1,2,3,4,5,6,7,8};
        const uint8_t  ro4[4]={CONF_ACTION_ROLE_INPUT,CONF_ACTION_ROLE_OUTPUT,
                               CONF_ACTION_ROLE_FEE,CONF_ACTION_ROLE_FEE};
        const uint64_t p4[4]={1,2,3,4}, nk4[4]={9,0,0,0}, ak4[4]={8,0,0,0};
        ci=inst; ci.value=v4; ci.addr=a4; ci.rcm=r4; ci.roles=ro4;
        ci.pos=p4; ci.nk=nk4; ci.ak=ak4; ci.num_notes=4; /* +1 dummy > 4 blocks */
        if(dnac_action_prover_prove(&ci,&bad)!=DNAC_PROVER_ERR_RANGE)ok=0;
        /* (d) NON-CANONICAL OUTPUT addr lane (== p) — red-team S1f F1 fix: the
         * raw ADDR cell would diverge from the reduced poseidon input; generate
         * fail-closes so the C<->Rust trace byte-identity can never break. */
        const uint64_t a_nc[3*4]={ 0,0,0,0, GOLDILOCKS_P,0xAA02,0xAA03,0xAA04,
                                   0xFEE1,0xFEE2,0xFEE3,0xFEE4 };
        ci=inst; ci.addr=a_nc;
        if(dnac_action_prover_prove(&ci,&bad)!=DNAC_PROVER_ERR_RANGE)ok=0;
        printf("  T8 (S1e.5+F1) cheat instances fail to prove (4/4 RANGE) %s\n",
               ok?"PASS":"FAIL");
        if(!ok)fails++;
    }

    dnac_action_prover_proof_free(pf);
    free(draws);
    if(fails){ printf("test_prover_action: FAIL (%d)\n",fails); free(fx); return 1; }
    printf("test_prover_action: PASS\n");
    printf("  pure-C C1 Action prove (width 813, num_qc=8, 0 publics) byte-matches\n");
    printf("  the REAL Plonky3 is_zk=1 proof (zeta+roots+final_poly) and self-verifies\n");
    printf("  (FRI DNAC_FRI_OK + N-chunk constraint check). Rust-free end-to-end.\n");
    free(fx);
    return 0;
}
