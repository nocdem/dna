/**
 * @file test_prover_agg.c
 * @brief Dual-mode S4b.4 — pure-C AGGREGATE prover byte-match vs the REAL
 *        Plonky3 proof (width 1936, is_zk=1, num_qc=8, 21 publics).
 *
 * Rebuilds the oracle instance (dump_conf_action_agg_air_zk: INPUT 100 = OUTPUT
 * 70 + FEE 30 + dummy-last, D=4 membership, log_height=7) + the SmallRng(1) draw
 * stream, runs dnac_agg_prover_prove, and byte-matches against
 * tools/vectors/conf_action_agg_air_zk.json:
 *
 *   T2  prove == OK (self-verify: priming zeta + FRI + N-chunk constraint check)
 *   T3  zeta + zeta_next == the REAL proof's challenges
 *   T4  trace/quotient/random roots == the REAL proof's commitments
 *   T5  final_poly == the REAL proof's final_poly
 *   T6  publics (anchor||num_input||nf_slots) == the REAL proof's public_values
 *   T7  fail-close: wrong draw count -> PARAM
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "conf_action_air.h"   /* conf_action_derive_addr */
#include "field_goldilocks.h"
#include "note_commit.h"       /* note_commit (build multi-input siblings) */
#include "stark_prover_agg.h"

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
#define TP_PUB 32

typedef struct {
    size_t degree_bits;
    gold_fp2_t zeta, zeta_next;
    uint8_t trace_root[64], quot_root[64], rand_root[64];
    gold_fp2_t final_poly[TP_FP]; size_t num_final_poly;
    uint64_t publics[TP_PUB]; size_t num_publics;
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
        } else if(strcmp(k,"public_values")==0){
            size_t n=0; js_match(s,'['); while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;} char*v=js_read_string(s); if(v&&n<TP_PUB)fx->publics[n]=strtoull(v,NULL,10); free(v); n++; } fx->num_publics=n;
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
    if(argc<3){ fprintf(stderr,"usage: %s <conf_action_agg_air_zk.json> <smallrng_goldilocks.json>\n",argv[0]); return 2; }
    tp_t *fx=(tp_t*)calloc(1,sizeof *fx); if(!fx)return 2;
    { size_t bl=0; char *blob=slurp(argv[1],&bl); if(!blob){ fprintf(stderr,"cannot read %s\n",argv[1]); return 2; }
      js_t s={blob,0,bl}; parse_vector(&s,fx); free(blob); }

    /* Instance selector: default 1-input (dump_conf_action_agg_air_zk); "2in" =
     * the two-input KAT (dump_conf_action_agg_air_zk_2in) — both at H=128. */
    const int two_in = (argc >= 4 && strcmp(argv[3], "2in") == 0);
    const unsigned log_height = 7;
    const size_t height = (size_t)1 << log_height;
    uint64_t value[3], addr[3*4], rcm[3*2], pos[3], nk[3], ak[3];
    uint8_t roles[3];
    uint64_t memb_siblings[3*4*4];
    size_t num_notes = 3;
    memset(memb_siblings, 0, sizeof memb_siblings);
    if (two_in) {
        /* 2 INPUT (60+40) = OUTPUT 100; the two inputs are level-0 SIBLINGS of
         * each other (pos 0 and 1) so both walks converge to ONE anchor. */
        const uint64_t v[3]={60,40,100};       memcpy(value,v,sizeof v);
        const uint8_t  r[3]={CONF_ACTION_ROLE_INPUT,CONF_ACTION_ROLE_INPUT,CONF_ACTION_ROLE_OUTPUT}; memcpy(roles,r,sizeof r);
        const uint64_t p[3]={0,1,0};           memcpy(pos,p,sizeof p);
        const uint64_t k[3]={0x22222222ULL,0x33333333ULL,0}; memcpy(nk,k,sizeof k);
        const uint64_t a[3]={0x11111111ULL,0x12121212ULL,0}; memcpy(ak,a,sizeof a);
        const uint64_t ad[3*4]={0,0,0,0, 0,0,0,0, 0xAA01,0xAA02,0xAA03,0xAA04}; memcpy(addr,ad,sizeof ad);
        const uint64_t rc[3*2]={0x11,0x12, 0x13,0x14, 0x21,0x22}; memcpy(rcm,rc,sizeof rc);
        /* compute the two inputs' cm and build sibling-of-each-other + shared upper. */
        uint64_t addr0[4],addr1[4],cm0[4],cm1[4];
        conf_action_derive_addr(ak[0],nk[0],addr0);  note_commit(value[0],addr0,&rcm[0],cm0);
        conf_action_derive_addr(ak[1],nk[1],addr1);  note_commit(value[1],addr1,&rcm[2],cm1);
        const uint64_t up[3][4]={{0x2001,0x2002,0x2003,0x2004},{0x3001,0x3002,0x3003,0x3004},{0x4001,0x4002,0x4003,0x4004}};
        for(int j=0;j<4;j++){ memb_siblings[0*16+0*4+j]=cm1[j]; memb_siblings[1*16+0*4+j]=cm0[j]; }
        for(int l=0;l<3;l++) for(int j=0;j<4;j++){ memb_siblings[0*16+(l+1)*4+j]=up[l][j]; memb_siblings[1*16+(l+1)*4+j]=up[l][j]; }
    } else {
        /* 1 INPUT 100 = OUTPUT 70 + FEE 30 (== dump_conf_action_agg_air_zk). */
        const uint64_t v[3]={100,70,30};       memcpy(value,v,sizeof v);
        const uint8_t  r[3]={CONF_ACTION_ROLE_INPUT,CONF_ACTION_ROLE_OUTPUT,CONF_ACTION_ROLE_FEE}; memcpy(roles,r,sizeof r);
        const uint64_t p[3]={5,0,0};           memcpy(pos,p,sizeof p);
        const uint64_t k[3]={0x22222222ULL,0,0}; memcpy(nk,k,sizeof k);
        const uint64_t a[3]={0x11111111ULL,0,0}; memcpy(ak,a,sizeof a);
        const uint64_t ad[3*4]={0,0,0,0, 0xAA01,0xAA02,0xAA03,0xAA04, 0xFEE1,0xFEE2,0xFEE3,0xFEE4}; memcpy(addr,ad,sizeof ad);
        const uint64_t rc[3*2]={0x11,0x12, 0x21,0x22, 0x31,0x32}; memcpy(rcm,rc,sizeof rc);
        const uint64_t sib[3*4*4]={
            0x1001,0x1002,0x1003,0x1004, 0x2001,0x2002,0x2003,0x2004,
            0x3001,0x3002,0x3003,0x3004, 0x4001,0x4002,0x4003,0x4004,
            0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
        memcpy(memb_siblings,sib,sizeof sib);
    }

    const size_t need = DNAC_AGG_PROVER_TOTAL_DRAWS(height);
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

    dnac_agg_prover_instance_t inst; memset(&inst,0,sizeof inst);
    inst.value=value; inst.addr=addr; inst.rcm=rcm; inst.roles=roles;
    inst.pos=pos; inst.nk=nk; inst.ak=ak; inst.num_notes=num_notes;
    inst.memb_siblings=memb_siblings;
    inst.log_height=log_height; inst.draws=draws; inst.num_draws=need;

    int fails=0;
    printf("── aggregate instance (%s): height=%zu num_notes=%zu degree_bits=%zu draws=%zu\n",
           two_in?"2-INPUT":"1-input", height, num_notes, fx->degree_bits, need);

    dnac_agg_prover_proof_t *pf=NULL;
    dnac_prover_status_t st=dnac_agg_prover_prove(&inst,&pf);
    printf("  T2 dnac_agg_prover_prove -> OK (self-verified)        %s\n",
           st==DNAC_PROVER_OK?"PASS":"FAIL");
    if(st!=DNAC_PROVER_OK){ printf("     status=%d\n",(int)st); free(fx); free(draws); return 1; }

    {
        gold_fp2_t z,zn; dnac_agg_prover_proof_zeta(pf,&z,&zn);
        int ok=gold_fp2_eq(z,fx->zeta)&&gold_fp2_eq(zn,fx->zeta_next);
        printf("  T3 zeta + zeta_next == REAL proof challenges          %s\n", ok?"PASS":"FAIL");
        if(!ok)fails++;
    }
    {
        uint8_t tr[64],qr[64],rr[64];
        dnac_agg_prover_proof_roots(pf,tr,qr,rr);
        int ok=!memcmp(tr,fx->trace_root,64)&&!memcmp(qr,fx->quot_root,64)&&!memcmp(rr,fx->rand_root,64);
        printf("  T4 trace/quotient/random roots == REAL commitments    %s\n", ok?"PASS":"FAIL");
        if(!ok)fails++;
    }
    {
        size_t n=0; const gold_fp2_t *fp=dnac_agg_prover_proof_final_poly(pf,&n);
        int ok=(n==fx->num_final_poly);
        for(size_t i=0;ok&&i<n;i++) if(!gold_fp2_eq(fp[i],fx->final_poly[i]))ok=0;
        printf("  T5 final_poly (%zu fp2) == REAL proof                  %s\n", n,ok?"PASS":"FAIL");
        if(!ok)fails++;
    }
    {
        size_t n=0; const gold_fp_t *pub=dnac_agg_prover_proof_publics(pf,&n);
        int ok=(n==fx->num_publics);
        for(size_t i=0;ok&&i<n;i++) if(gold_fp_to_u64(pub[i])!=fx->publics[i])ok=0;
        printf("  T6 publics (%zu = anchor||num_input||nf_slots) == REAL  %s\n", n,ok?"PASS":"FAIL");
        if(!ok)fails++;
    }
    {
        int ok=1;
        dnac_agg_prover_proof_t *bad=NULL;
        dnac_agg_prover_instance_t bi=inst; bi.num_draws=need-1;
        if(dnac_agg_prover_prove(&bi,&bad)!=DNAC_PROVER_ERR_PARAM)ok=0;
        printf("  T7 fail-close: wrong draw count -> PARAM              %s\n", ok?"PASS":"FAIL");
        if(!ok)fails++;
    }

    /* T8 (S4b.5) — cheat instances FAIL to prove through the real prover. The
     * honest-prover preconditions (conf_action_air_generate: balance, range,
     * budget, canonical lanes) plus the aggregate anchor-consistency check
     * fail-close BEFORE a proof is produced. (The complementary "tampered proof
     * -> OOD" half is test_conf_action_agg_verify T7; construction-gate mint /
     * double-spend / nf-drop/add soundness is test_conf_action_agg_air 14/14.) */
    if(!two_in){
        int ok=1;
        dnac_agg_prover_proof_t *bad=NULL;
        /* (a) non-conserving balance: INPUT 100 != OUTPUT 60 + FEE 30. */
        const uint64_t v_bad[3]={100,60,30};
        dnac_agg_prover_instance_t ci=inst; ci.value=v_bad;
        if(dnac_agg_prover_prove(&ci,&bad)!=DNAC_PROVER_ERR_RANGE)ok=0;
        /* (b) value >= 2^52 (range overflow). */
        const uint64_t v_ovf[3]={ (uint64_t)1<<52, ((uint64_t)1<<52)-30, 30 };
        ci=inst; ci.value=v_ovf;
        if(dnac_agg_prover_prove(&ci,&bad)!=DNAC_PROVER_ERR_RANGE)ok=0;
        /* (c) NON-CANONICAL OUTPUT addr lane (== p): generate fail-closes so the
         * C<->Rust trace byte-identity can never break (red-team S1f F1). */
        const uint64_t a_nc[3*4]={ 0,0,0,0, GOLDILOCKS_P,0xAA02,0xAA03,0xAA04,
                                   0xFEE1,0xFEE2,0xFEE3,0xFEE4 };
        ci=inst; ci.addr=a_nc;
        if(dnac_agg_prover_prove(&ci,&bad)!=DNAC_PROVER_ERR_RANGE)ok=0;
        /* (d) aggregate-specific: a NULL sibling set with an INPUT note -> the
         * membership walk cannot run -> agg_zk_generate fail-closes (RANGE). */
        ci=inst; ci.memb_siblings=NULL;
        if(dnac_agg_prover_prove(&ci,&bad)!=DNAC_PROVER_ERR_RANGE)ok=0;
        printf("  T8 (S4b.5) cheat instances fail to prove (4/4 RANGE)  %s\n",
               ok?"PASS":"FAIL");
        if(!ok)fails++;
    }

    dnac_agg_prover_proof_free(pf);
    free(draws);
    if(fails){ printf("test_prover_agg: FAIL (%d)\n",fails); free(fx); return 1; }
    printf("test_prover_agg: PASS\n");
    printf("  pure-C AGGREGATE prove (width 1936, num_qc=8, 21 publics) byte-matches\n");
    printf("  the REAL Plonky3 is_zk=1 proof (zeta+roots+final_poly+publics) and\n");
    printf("  self-verifies (FRI + N-chunk constraint check). Rust-free end-to-end.\n");
    free(fx);
    return 0;
}
