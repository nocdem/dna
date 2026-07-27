/**
 * @file test_prover_agg.c
 * @brief Dual-mode S4b.4 — pure-C AGGREGATE prover byte-match vs the REAL
 *        Plonky3 proof (width 2318 post-F3, is_zk=1, num_qc=8, 43 publics).
 *
 * d4.c-2 (2026-07-26): dnac_agg_prover_prove now DELEGATES to dnac_batch_prove
 * (1-instance is_zk=1 batch) — the v3 uni-stark pipeline retired. This test
 * re-anchored onto tools/vectors/batch_shielded_agg.json (the BATCHED agg
 * vectors: agg_1in / 2in / 4in plain + *_salted); it checks the delegation
 * wrapper's accessors (zeta/roots/final_poly/publics) byte-match the oracle —
 * the FULL proof byte-match lives in test_batch_shielded_agg (d4.c-1).
 *
 * Rebuilds the oracle instance (1-input: INPUT 100 = OUTPUT 70 + FEE 30, D=4
 * membership, log_height=7; 2in/4in variants) + the SmallRng(1) draw stream,
 * runs dnac_agg_prover_prove, and byte-matches against the named scenario in
 * tools/vectors/batch_shielded_agg.json:
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
/* P1c: 32 wire bytes -> 4 LE u64 lanes (endian-explicit, no memcpy punning). */
static void p2_digest_from_le_bytes(const uint8_t b[32], dnac_p2_digest_t *d){
    for(size_t l=0;l<4;l++){ uint64_t v=0; for(size_t i=0;i<8;i++) v|=(uint64_t)b[l*8+i]<<(8*i); d->lanes[l]=v; }
}
static gold_fp2_t parse_fp2_decimal(js_t *s){
    uint64_t c0=0,c1=0; js_match(s,'{');
    while(!js_match(s,'}')){ if(js_peek(s,',')){s->pos++;continue;} char*k=js_read_string(s); js_match(s,':'); char*v=js_peek(s,'"')?js_read_string(s):NULL;
        if(v&&k&&strcmp(k,"c0_decimal")==0)c0=strtoull(v,NULL,10); else if(v&&k&&strcmp(k,"c1_decimal")==0)c1=strtoull(v,NULL,10); else if(!v)js_skip_value(s); free(v); free(k); }
    return gold_fp2_new(gold_fp_from_u64(c0),gold_fp_from_u64(c1));
}
/* Goldilocks serde: v0.6.2 emits a BARE number where 82cfad73 emitted the
 * wrapped {"value": N} (compare the two batch_shielded_agg.json revisions:
 * cap [[2369166141762287410, ...]] vs cap [[{"value":2369166141762287410},...]]).
 * Both forms are accepted so this parser reads either vintage.
 *
 * The no-progress guard is NOT cosmetic: without it the bare-number form made
 * this loop spin forever — js_match('{') failed, js_read_string returned NULL,
 * js_match(':') failed, and nothing advanced s->pos. The test emitted nothing
 * and looked exactly like a crypto hang. A parser that cannot advance must
 * fail, not wedge. (Same fix as tests/test_batch_shielded_agg.c; the identical
 * parser is also in test_fri_verifier_{rollin,valid}.c, which still read
 * 82cfad73-era vectors and will need it when S2'-f regenerates theirs.) */
static uint64_t parse_base_obj(js_t *s){
    uint64_t r=0;
    js_skip_ws(s);
    if(s->pos<s->len && s->src[s->pos]!='{'){ js_read_u64(s,&r); return r; }
    js_match(s,'{');
    while(!js_match(s,'}')){
        if(js_peek(s,',')){s->pos++;continue;}
        const size_t before=s->pos;
        char*k=js_read_string(s); js_match(s,':');
        if(k&&strcmp(k,"value")==0)js_read_u64(s,&r); else js_skip_value(s);
        free(k);
        if(s->pos==before) break;   /* unparsable token: bail, never spin */
    }
    return r;
}
static gold_fp2_t parse_fp2_wrapped(js_t *s){
    uint64_t comps[2]={0,0}; int n=0; js_match(s,'{');
    while(!js_match(s,'}')){ if(js_peek(s,',')){s->pos++;continue;} char*k=js_read_string(s); js_match(s,':');
        if(k&&strcmp(k,"value")==0){ js_match(s,'['); while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;} uint64_t bv=parse_base_obj(s); if(n<2)comps[n]=bv; n++; } } else { js_skip_value(s); } free(k); }
    return gold_fp2_new(gold_fp_from_u64(comps[0]),gold_fp_from_u64(comps[1]));
}

#define TP_FP 16
#define TP_PUB 48  /* covers the 43 S4c publics (anchor||num_in||nf||num_out||ocommit||fee||txbind) */

typedef struct {
    char name[64];
    size_t degree_bits;
    gold_fp2_t zeta, zeta_next;
    dnac_p2_digest_t trace_root, quot_root, rand_root; /* P1c: 4-lane */
    gold_fp2_t final_poly[TP_FP]; size_t num_final_poly;
    uint64_t publics[TP_PUB]; size_t num_publics;
} tp_t;

/* d4.c-2: the agg prover now DELEGATES to dnac_batch_prove, so test_prover_agg
 * byte-matches the wrapper accessors (zeta/zeta_next/roots/final_poly/publics)
 * against the BATCHED shielded-agg oracle (tools/vectors/batch_shielded_agg.json,
 * scenarios agg_1in / agg_2in / agg_4in — the PLAIN unsalted ones dnac_agg_
 * prover_prove reproduces; the full byte-match lives in test_batch_shielded_agg). */

/* Read the fields from ONE scenario object (js_t at its opening '{'). */
static void parse_scenario_fields(js_t *s, tp_t *fx){
    js_match(s,'{');
    while(!js_match(s,'}')){ if(js_peek(s,',')){s->pos++;continue;} char*k=js_read_string(s); if(!k)break; js_match(s,':');
        if(strcmp(k,"name")==0){ char*v=js_peek(s,'"')?js_read_string(s):NULL; if(v){ strncpy(fx->name,v,sizeof fx->name-1); free(v);} else js_skip_value(s); }
        else if(strcmp(k,"degree_bits")==0){ uint64_t v=0; js_match(s,'['); if(!js_match(s,']')){ js_read_u64(s,&v); while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;} js_skip_value(s);} } fx->degree_bits=(size_t)v; }
        else if(strcmp(k,"zeta")==0){ fx->zeta=parse_fp2_decimal(s); }
        else if(strcmp(k,"commits")==0){
            js_match(s,'{'); while(!js_match(s,'}')){ if(js_peek(s,',')){s->pos++;continue;} char*ck=js_read_string(s); js_match(s,':');
                if(ck&&strcmp(ck,"main")==0){ char*h=js_peek(s,'"')?js_read_string(s):NULL; if(h){uint8_t b[32]; hex_decode(h,b,32); p2_digest_from_le_bytes(b,&fx->trace_root); free(h);} else js_skip_value(s); }
                else if(ck&&strcmp(ck,"quotient")==0){ char*h=js_peek(s,'"')?js_read_string(s):NULL; if(h){uint8_t b[32]; hex_decode(h,b,32); p2_digest_from_le_bytes(b,&fx->quot_root); free(h);} else js_skip_value(s); }
                else if(ck&&strcmp(ck,"random")==0){ char*h=js_peek(s,'"')?js_read_string(s):NULL; if(h){uint8_t b[32]; hex_decode(h,b,32); p2_digest_from_le_bytes(b,&fx->rand_root); free(h);} else js_skip_value(s); }
                else js_skip_value(s);
                free(ck); }
        }
        else if(strcmp(k,"instances")==0){
            js_match(s,'['); js_match(s,'{'); /* instances[0] */
            while(!js_match(s,'}')){ if(js_peek(s,',')){s->pos++;continue;} char*ik=js_read_string(s); js_match(s,':');
                if(ik&&strcmp(ik,"zeta_next")==0)fx->zeta_next=parse_fp2_decimal(s);
                else if(ik&&strcmp(ik,"public_values")==0){ size_t n=0; js_match(s,'['); while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;} char*v=js_read_string(s); if(v){ if(n<TP_PUB)fx->publics[n]=strtoull(v,NULL,10); free(v); n++; } else { js_skip_value(s); } } fx->num_publics=n; }
                else js_skip_value(s);
                free(ik); }
            while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;} js_skip_value(s);}
        }
        else if(strcmp(k,"proof_serde")==0){
            js_match(s,'{'); while(!js_match(s,'}')){ if(js_peek(s,',')){s->pos++;continue;} char*pk=js_read_string(s); js_match(s,':');
                if(pk&&strcmp(pk,"opening_proof")==0){
                    js_match(s,'['); js_skip_value(s); if(js_peek(s,',')) s->pos++; /* skip rand_openings */
                    js_match(s,'{'); /* friproof */
                    while(!js_match(s,'}')){ if(js_peek(s,',')){s->pos++;continue;} char*fk=js_read_string(s); js_match(s,':');
                        if(fk&&strcmp(fk,"final_poly")==0){ size_t n=0; js_match(s,'['); while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;} gold_fp2_t fv=parse_fp2_wrapped(s); if(n<TP_FP)fx->final_poly[n]=fv; n++; } fx->num_final_poly=n; }
                        else js_skip_value(s);
                        free(fk); }
                    while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;} js_skip_value(s);}
                } else js_skip_value(s);
                free(pk); }
        }
        else js_skip_value(s);
        free(k);
    }
}

/* Find the named scenario in batch_shielded_agg.json + extract its fields. */
static int parse_vector(js_t *s, tp_t *fx, const char *scen_name){
    js_match(s,'{');
    while(!js_match(s,'}')){ if(js_peek(s,',')){s->pos++;continue;} char*k=js_read_string(s); if(!k)break; js_match(s,':');
        if(strcmp(k,"scenarios")==0){
            js_match(s,'[');
            while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;}
                tp_t tmp; memset(&tmp,0,sizeof tmp);
                parse_scenario_fields(s,&tmp);
                if(strcmp(tmp.name,scen_name)==0){ *fx=tmp; free(k); return 1; }
            }
            free(k); return 0;
        } else js_skip_value(s);
        free(k);
    }
    return 0;
}

int main(int argc,char **argv){
    if(argc<3){ fprintf(stderr,"usage: %s <batch_shielded_agg.json> <smallrng_goldilocks.json> [2in|4in] [--salted]\n",argv[0]); return 2; }
    tp_t *fx=(tp_t*)calloc(1,sizeof *fx); if(!fx)return 2;

    /* Instance selector: default 1-input; "2in"/"4in" select the batched
     * shielded-agg oracle scenario of the same shape (all at the plain 2-query
     * TEST params dnac_agg_prover_prove uses). */
    const int two_in  = (argc >= 4 && strcmp(argv[3], "2in") == 0);
    const int four_in = (argc >= 4 && strcmp(argv[3], "4in") == 0);
    int salted = 0;
    for (int ai = 3; ai < argc; ai++) if (strcmp(argv[ai], "--salted") == 0) salted = 1;
    const char *scen_name =
        salted ? (four_in ? "agg_4in_salted" : "agg_1in_salted")
               : (four_in ? "agg_4in" : two_in ? "agg_2in" : "agg_1in");
    { size_t bl=0; char *blob=slurp(argv[1],&bl); if(!blob){ fprintf(stderr,"cannot read %s\n",argv[1]); return 2; }
      js_t s={blob,0,bl}; if(!parse_vector(&s,fx,scen_name)){ fprintf(stderr,"scenario %s not found in %s\n",scen_name,argv[1]); free(blob); free(fx); return 2; } free(blob); }
    printf("── oracle scenario: %s (degree_bits=%zu, %zu publics, %zu final_poly)\n",
           scen_name, fx->degree_bits, fx->num_publics, fx->num_final_poly);

    const unsigned log_height = four_in ? 8 : 7;
    const size_t height = (size_t)1 << log_height;
    /* F3: nk/ak are 4-lane-per-block arrays ([blk*4 + lane]). */
    uint64_t value[5], addr[5*4], rcm[5*2], pos[5], nk[5*4], ak[5*4];
    uint8_t roles[5];
    uint64_t memb_siblings[5*4*4];
    size_t num_notes = 3;
    memset(memb_siblings, 0, sizeof memb_siblings);
    if (four_in) {
        /* 4 INPUT (25×4) = OUTPUT 100; all four in ONE depth-4 tree at pos 0..3
         * (leaves 0/1 and 2/3 pair, subtree roots pair at level 1) → one anchor.
         * Fills N_input to MAX_INPUTS=4 (all 4 slots) — the GAP-1 boundary. */
        num_notes = 5;
        for(int i=0;i<4;i++){ value[i]=25; roles[i]=CONF_ACTION_ROLE_INPUT; pos[i]=(uint64_t)i; }
        value[4]=100; roles[4]=CONF_ACTION_ROLE_OUTPUT; pos[4]=0;
        const uint64_t k[5*4]={0x22222222ULL,0x22222223ULL,0x22222224ULL,0x22222225ULL,
                               0x33333333ULL,0x33333334ULL,0x33333335ULL,0x33333336ULL,
                               0x44444444ULL,0x44444445ULL,0x44444446ULL,0x44444447ULL,
                               0x55555555ULL,0x55555556ULL,0x55555557ULL,0x55555558ULL,
                               0,0,0,0}; memcpy(nk,k,sizeof k);
        const uint64_t a[5*4]={0x11111111ULL,0x11111112ULL,0x11111113ULL,0x11111114ULL,
                               0x12121212ULL,0x12121213ULL,0x12121214ULL,0x12121215ULL,
                               0x13131313ULL,0x13131314ULL,0x13131315ULL,0x13131316ULL,
                               0x14141414ULL,0x14141415ULL,0x14141416ULL,0x14141417ULL,
                               0,0,0,0}; memcpy(ak,a,sizeof a);
        const uint64_t rc[5*2]={0x11,0x12, 0x13,0x14, 0x15,0x16, 0x17,0x18, 0x21,0x22}; memcpy(rcm,rc,sizeof rc);
        uint64_t ad[5*4]; memset(ad,0,sizeof ad);
        ad[4*4+0]=0xAA01; ad[4*4+1]=0xAA02; ad[4*4+2]=0xAA03; ad[4*4+3]=0xAA04; memcpy(addr,ad,sizeof ad);
        /* cm0..3 + internal nodes N01=compress(cm0,cm1), N23=compress(cm2,cm3). */
        uint64_t cm[4][4], adr[4];
        for(int i=0;i<4;i++){ conf_action_derive_addr(&ak[i*4],&nk[i*4],adr); note_commit(25,adr,&rcm[i*2],cm[i]); }
        uint64_t n01[4], n23[4];
        note_merkle_compress(cm[0],cm[1],n01);
        note_merkle_compress(cm[2],cm[3],n23);
        const uint64_t e2[4]={0x3001,0x3002,0x3003,0x3004}, e3[4]={0x4001,0x4002,0x4003,0x4004};
        uint64_t *ms=memb_siblings;
        for(int j=0;j<4;j++){
            ms[0*16+0*4+j]=cm[1][j]; ms[0*16+1*4+j]=n23[j]; ms[0*16+2*4+j]=e2[j]; ms[0*16+3*4+j]=e3[j];
            ms[1*16+0*4+j]=cm[0][j]; ms[1*16+1*4+j]=n23[j]; ms[1*16+2*4+j]=e2[j]; ms[1*16+3*4+j]=e3[j];
            ms[2*16+0*4+j]=cm[3][j]; ms[2*16+1*4+j]=n01[j]; ms[2*16+2*4+j]=e2[j]; ms[2*16+3*4+j]=e3[j];
            ms[3*16+0*4+j]=cm[2][j]; ms[3*16+1*4+j]=n01[j]; ms[3*16+2*4+j]=e2[j]; ms[3*16+3*4+j]=e3[j];
        }
    } else if (two_in) {
        /* 2 INPUT (60+40) = OUTPUT 100; the two inputs are level-0 SIBLINGS of
         * each other (pos 0 and 1) so both walks converge to ONE anchor. */
        const uint64_t v[3]={60,40,100};       memcpy(value,v,sizeof v);
        const uint8_t  r[3]={CONF_ACTION_ROLE_INPUT,CONF_ACTION_ROLE_INPUT,CONF_ACTION_ROLE_OUTPUT}; memcpy(roles,r,sizeof r);
        const uint64_t p[3]={0,1,0};           memcpy(pos,p,sizeof p);
        const uint64_t k[3*4]={0x22222222ULL,0x22222223ULL,0x22222224ULL,0x22222225ULL,
                               0x33333333ULL,0x33333334ULL,0x33333335ULL,0x33333336ULL,
                               0,0,0,0}; memcpy(nk,k,sizeof k);
        const uint64_t a[3*4]={0x11111111ULL,0x11111112ULL,0x11111113ULL,0x11111114ULL,
                               0x12121212ULL,0x12121213ULL,0x12121214ULL,0x12121215ULL,
                               0,0,0,0}; memcpy(ak,a,sizeof a);
        const uint64_t ad[3*4]={0,0,0,0, 0,0,0,0, 0xAA01,0xAA02,0xAA03,0xAA04}; memcpy(addr,ad,sizeof ad);
        const uint64_t rc[3*2]={0x11,0x12, 0x13,0x14, 0x21,0x22}; memcpy(rcm,rc,sizeof rc);
        /* compute the two inputs' cm and build sibling-of-each-other + shared upper. */
        uint64_t addr0[4],addr1[4],cm0[4],cm1[4];
        conf_action_derive_addr(&ak[0],&nk[0],addr0);  note_commit(value[0],addr0,&rcm[0],cm0);
        conf_action_derive_addr(&ak[4],&nk[4],addr1);  note_commit(value[1],addr1,&rcm[2],cm1);
        const uint64_t up[3][4]={{0x2001,0x2002,0x2003,0x2004},{0x3001,0x3002,0x3003,0x3004},{0x4001,0x4002,0x4003,0x4004}};
        for(int j=0;j<4;j++){ memb_siblings[0*16+0*4+j]=cm1[j]; memb_siblings[1*16+0*4+j]=cm0[j]; }
        for(int l=0;l<3;l++) for(int j=0;j<4;j++){ memb_siblings[0*16+(l+1)*4+j]=up[l][j]; memb_siblings[1*16+(l+1)*4+j]=up[l][j]; }
    } else {
        /* 1 INPUT 100 = OUTPUT 70 + FEE 30 (== dump_conf_action_agg_air_zk). */
        const uint64_t v[3]={100,70,30};       memcpy(value,v,sizeof v);
        const uint8_t  r[3]={CONF_ACTION_ROLE_INPUT,CONF_ACTION_ROLE_OUTPUT,CONF_ACTION_ROLE_FEE}; memcpy(roles,r,sizeof r);
        const uint64_t p[3]={5,0,0};           memcpy(pos,p,sizeof p);
        const uint64_t k[3*4]={0x22222222ULL,0x22222223ULL,0x22222224ULL,0x22222225ULL,
                               0,0,0,0, 0,0,0,0}; memcpy(nk,k,sizeof k);
        const uint64_t a[3*4]={0x11111111ULL,0x11111112ULL,0x11111113ULL,0x11111114ULL,
                               0,0,0,0, 0,0,0,0}; memcpy(ak,a,sizeof a);
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
    /* Sample KAT tx_binding — MUST match the oracle's AGG_KAT_TXBIND (production
     * uses conf_txbind_map(sighash_v4)). Proves the interface carries a real
     * caller-provided tx_binding (not hardcoded 0) + the proof FS-welds to it. */
    static const uint64_t kat_txbind[4] = {
        0x1111111111111111ULL, 0x2222222222222222ULL,
        0x3333333333333333ULL, 0x4444444444444444ULL };
    inst.tx_binding=kat_txbind;
    inst.log_height=log_height; inst.draws=draws; inst.num_draws=need;
    /* P4: --salted reuses the same SmallRng(1) draws buffer as the salt stream
     * (need=2040h >= 160h). Must match the oracle's make_salted_zk_config (seed=1). */
    if (salted) { inst.salt_draws=draws; inst.num_salt_draws=need; }

    int fails=0;
    printf("── aggregate instance (%s): height=%zu num_notes=%zu degree_bits=%zu draws=%zu\n",
           four_in?"4-INPUT":two_in?"2-INPUT":"1-input", height, num_notes, fx->degree_bits, need);

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
        dnac_p2_digest_t tr,qr,rr;
        dnac_agg_prover_proof_roots(pf,&tr,&qr,&rr);
        int ok=!memcmp(&tr,&fx->trace_root,sizeof tr)&&!memcmp(&qr,&fx->quot_root,sizeof qr)&&!memcmp(&rr,&fx->rand_root,sizeof rr);
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
    if(!two_in && !four_in){
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
    printf("  pure-C AGGREGATE prove (width %d, num_qc=8, 43 publics) byte-matches\n",
           (int)CONF_AGGZK_WIDTH);
    printf("  the REAL Plonky3 is_zk=1 proof (zeta+roots+final_poly+publics) and\n");
    printf("  self-verifies (FRI + N-chunk constraint check). Rust-free end-to-end.\n");
    free(fx);
    return 0;
}
