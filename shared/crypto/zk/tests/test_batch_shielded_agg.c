/**
 * @file test_batch_shielded_agg.c
 * @brief P2L-d d4.c-1 KAT — the FIRST validation of the SALTED batched STARK
 *        prover (`dnac_batch_prove`, salt_elems=2) byte-matched against the REAL
 *        Plonky3 prove_batch shielded-aggregate vectors
 *        (tools/vectors/batch_shielded_agg.json, every scenario
 *        verify_batch-gated + num_qc==8-gated in-oracle at 82cfad73).
 *
 * The v3 aggregate Action AIR fixtures (1in / 1in salted / 2in / 4in / 4in
 * salted) are re-proved via prove_batch as 1-instance is_zk=1 batches. For each
 * the C KAT rebuilds the SAME notes/siblings witness (== test_prover_agg), runs
 * the aggregate S1 generator (dnac_agg_zk_generate_trace_testonly) to get the
 * raw CONF_AGGZK_WIDTH-wide base trace + CONF_AGGZK_NUM_PUBLICS publics, then
 * proves the 1-instance batch from scratch through dnac_batch_prove and
 * byte-matches EVERYTHING:
 *   - commitments (main / quotient / random present; prep / perm absent)
 *   - the sampled constraint-α and ζ
 *   - the OOD opened values (trace_local[W], trace_next[W],
 *     quotient_chunks[8][2], random[2]; permutation empty)
 *   - the ENTIRE FRI opening proof (commit-phase commits, PoW witnesses, final
 *     poly, per-query input rows + sibling paths + commit-phase steps)
 *   - the hiding rand-openings, entry per entry
 *   - the M3b LEAF SALTS on the salted scenarios (input-batch salts per matrix +
 *     commit-phase step salts) — the d4.c-1 deliverable; the root match already
 *     transitively pins that the salts entered the leaves, the explicit salt
 *     match is belt-and-suspenders.
 *
 * Draw + salt streams = tools/vectors/smallrng_goldilocks.json: the C prover
 * reuses ONE dumped SmallRng(1) stream for the zk draws AND the input-mmcs salt
 * stream A (make_salted_zk_config uses three same-seed SmallRng(1) instances);
 * fri_salt_draws is left NULL → falls back to salt_draws@0 (the FRI-mmcs
 * clone-seed parity, P1e-HIGH1).
 *
 * dnac_batch_prove self-verifies (runs dnac_batch_verify internally) before
 * returning — a successful prove already means the salted proof VERIFIES; the
 * byte-match then pins it to Plonky3 exactly.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "batch_prover.h"
#include "conf_action_agg_fold.h" /* DNAC_CONF_ACTION_AGG_FOLD_AIR, CONF_AGGZK_* */
#include "conf_action_air.h"      /* conf_action_derive_addr, CONF_ACTION_ROLE_* */
#include "field_goldilocks.h"
#include "note_commit.h"          /* note_commit, note_merkle_compress */
#include "stark_prover_agg.h"     /* dnac_agg_zk_generate_trace_testonly */

/* ===== streaming JSON scanner (== test_prover_agg.c; proven on the 17MB
 * smallrng file) ===== */
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
static void p2_digest_from_le_bytes(const uint8_t b[32], dnac_p2_digest_t *d){
    for(size_t l=0;l<4;l++){ uint64_t v=0; for(size_t i=0;i<8;i++) v|=(uint64_t)b[l*8+i]<<(8*i); d->lanes[l]=v; }
}
/* friendly fp2 ({c0_decimal,c1_decimal}) — the OOD openings + alpha/zeta. */
static gold_fp2_t parse_fp2_decimal(js_t *s){
    uint64_t c0=0,c1=0; js_match(s,'{');
    while(!js_match(s,'}')){ if(js_peek(s,',')){s->pos++;continue;} char*k=js_read_string(s); js_match(s,':'); char*v=js_peek(s,'"')?js_read_string(s):NULL;
        if(v&&k&&strcmp(k,"c0_decimal")==0)c0=strtoull(v,NULL,10); else if(v&&k&&strcmp(k,"c1_decimal")==0)c1=strtoull(v,NULL,10); else if(!v)js_skip_value(s); free(v); free(k); }
    return gold_fp2_new(gold_fp_from_u64(c0),gold_fp_from_u64(c1));
}
/* serde base scalar {"value":N} → u64. */
/* Goldilocks serde: v0.6.2 emits a BARE number where 82cfad73 emitted the
 * wrapped {"value": N} (compare the two batch_shielded_agg.json revisions:
 * cap [[2369166141762287410, ...]] vs cap [[{"value":2369166141762287410},...]]).
 * Both forms are accepted so this parser reads either vintage.
 *
 * The no-progress guard is NOT cosmetic: without it the bare-number form made
 * this loop spin forever — js_match('{') failed, js_read_string returned NULL,
 * js_match(':') failed, and nothing advanced s->pos. A 41-second test ran past
 * 15 minutes with no output and looked exactly like a crypto hang. A parser
 * that cannot advance must fail, not wedge. */
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
/* serde ext {"_phantom":null,"value":[{value},{value}]} → fp2. */
static gold_fp2_t parse_fp2_wrapped(js_t *s){
    uint64_t comps[2]={0,0}; int n=0; js_match(s,'{');
    while(!js_match(s,'}')){ if(js_peek(s,',')){s->pos++;continue;} char*k=js_read_string(s); js_match(s,':');
        if(k&&strcmp(k,"value")==0){ js_match(s,'['); while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;} uint64_t bv=parse_base_obj(s); if(n<2)comps[n]=bv; n++; } } else { js_skip_value(s); } free(k); }
    return gold_fp2_new(gold_fp_from_u64(comps[0]),gold_fp_from_u64(comps[1]));
}
/* serde digest [{value}×4] → 4 lanes (used inside the cap:[[..]] wrapper). */
static void parse_digest_arr(js_t *s, dnac_p2_digest_t *d){
    size_t k=0; js_match(s,'[');
    while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;} uint64_t v=parse_base_obj(s); if(k<4)d->lanes[k]=v; k++; }
}

/* ===== extracted oracle scenario (heap-calloc'd, one at a time) ===== */
#define OV_MAXQ     2
#define OV_MAXB     3
#define OV_MAXM     8      /* quotient batch = 8 chunk matrices */
/* trace committed width (CONF_AGGZK_WIDTH + 4 zk codewords) — macro-derived so
 * an AIR width change (S8 Gate 2 moved it 2318 -> 2378 at D=24) cannot silently
 * truncate the parse into a false byte-match. */
#define OV_MAXW     (CONF_AGGZK_WIDTH + 4)
#define OV_MAXDEPTH 12
#define OV_MAXCPC   8
#define OV_MAXSE    4
#define OV_MAXFP    8
#define OV_MAXRO    16     /* rand-openings entries */
#define OV_MAXROV   8      /* fp2 per rand-opening entry (num_random_codewords) */

typedef struct {
    char     name[64];
    int      is_zk;
    uint64_t salted;                  /* 0 or 2 (SALT_ELEMS) */
    size_t   degree_bits;             /* top-level degree_bits[0] */

    int have_main, have_prep, have_perm, have_quot, have_rand;
    dnac_p2_digest_t main_c, quot_c, rand_c;
    gold_fp2_t alpha, zeta;

    gold_fp2_t trace_local[OV_MAXW]; size_t trace_local_len;
    gold_fp2_t trace_next[OV_MAXW];  size_t trace_next_len;
    gold_fp2_t quot_chunks[16][2];   size_t nqc;
    gold_fp2_t random[OV_MAXROV];    size_t random_len;
    size_t perm_local_len, perm_next_len;
    uint64_t pub[64]; size_t n_pub;

    dnac_p2_digest_t cpc[OV_MAXCPC]; size_t n_cpc;
    gold_fp_t        cpw[OV_MAXCPC]; size_t n_cpw;
    gold_fp2_t       final_poly[OV_MAXFP]; size_t n_fp;
    gold_fp_t        qpw;
    size_t           n_q;

    /* input batches */
    size_t           ib_nmat[OV_MAXQ][OV_MAXB];
    size_t           ib_w[OV_MAXQ][OV_MAXB][OV_MAXM];
    gold_fp_t        ib_ov[OV_MAXQ][OV_MAXB][OV_MAXM][OV_MAXW];
    size_t           ib_depth[OV_MAXQ][OV_MAXB];
    dnac_p2_digest_t ib_sib[OV_MAXQ][OV_MAXB][OV_MAXDEPTH];
    size_t           ib_se[OV_MAXQ][OV_MAXB];
    gold_fp_t        ib_salt[OV_MAXQ][OV_MAXB][OV_MAXM][OV_MAXSE];

    /* commit-phase steps */
    size_t           cp_nsteps[OV_MAXQ];
    uint8_t          cp_la[OV_MAXQ][OV_MAXCPC];
    size_t           cp_nsv[OV_MAXQ][OV_MAXCPC];
    gold_fp2_t       cp_sv[OV_MAXQ][OV_MAXCPC][4];
    size_t           cp_depth[OV_MAXQ][OV_MAXCPC];
    dnac_p2_digest_t cp_sib[OV_MAXQ][OV_MAXCPC][OV_MAXDEPTH];
    size_t           cp_se[OV_MAXQ][OV_MAXCPC];
    gold_fp_t        cp_salt[OV_MAXQ][OV_MAXCPC][OV_MAXSE];

    /* rand openings (flattened [round][mat][point] → entry of codewords) */
    size_t           n_ro;
    size_t           ro_len[OV_MAXRO];
    gold_fp2_t       ro_val[OV_MAXRO][OV_MAXROV];
} ov_t;

/* ── opened_values [mat][col] of base scalars → ib_ov[q][b] ── */
static int parse_opened_values(js_t *s, ov_t *o, size_t q, size_t b){
    size_t m=0; if(!js_match(s,'['))return 0;
    while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;}
        size_t c=0; js_match(s,'[');
        while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;} uint64_t v=parse_base_obj(s); if(m<OV_MAXM&&c<OV_MAXW)o->ib_ov[q][b][m][c]=gold_fp_from_u64(v); c++; }
        if(m<OV_MAXM){ o->ib_w[q][b][m]=c; }
        m++;
    }
    o->ib_nmat[q][b]=m; return 1;
}
/* digest-list [depth][4 scalars] → siblings out[]; returns depth. */
static size_t parse_sib_list(js_t *s, dnac_p2_digest_t *out){
    size_t d=0; js_match(s,'[');
    while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;} dnac_p2_digest_t dg={{0,0,0,0}}; parse_digest_arr(s,&dg); if(d<OV_MAXDEPTH)out[d]=dg; d++; }
    return d;
}
/* salts [nmat][SE scalars] → salt[m][*] + se; returns nmat (out_se set). */
static size_t parse_salt_list(js_t *s, gold_fp_t salt[OV_MAXM][OV_MAXSE], size_t *out_se){
    size_t m=0, se=0; js_match(s,'[');
    while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;}
        size_t k=0; js_match(s,'[');
        while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;} uint64_t v=parse_base_obj(s); if(m<OV_MAXM&&k<OV_MAXSE)salt[m][k]=gold_fp_from_u64(v); k++; }
        se=k; m++;
    }
    *out_se=se; return m;
}
/* Structural detector: opening_proof "[" then "[" then '[' => salted
 * ([salts,siblings]; salts[0] is a list), '{' => unsalted (digest scalars).
 * Non-consuming (saves/restores pos). */
static int opening_is_salted(js_t *s){
    size_t save=s->pos; int salted=0;
    if(js_match(s,'[') && js_match(s,'[')){ js_skip_ws(s); if(s->pos<s->len && s->src[s->pos]=='[') salted=1; }
    s->pos=save; return salted;
}

static void parse_input_batch(js_t *s, ov_t *o, size_t q, size_t b){
    js_match(s,'{');
    while(!js_match(s,'}')){ if(js_peek(s,',')){s->pos++;continue;} char*k=js_read_string(s); js_match(s,':');
        if(k&&strcmp(k,"opened_values")==0){ parse_opened_values(s,o,q,b); }
        else if(k&&strcmp(k,"opening_proof")==0){
            if(opening_is_salted(s)){
                js_match(s,'[');                                   /* [salts, siblings] */
                (void)parse_salt_list(s,o->ib_salt[q][b],&o->ib_se[q][b]);
                js_match(s,',') ; /* between salts and siblings (peek handles it) */
                o->ib_depth[q][b]=parse_sib_list(s,o->ib_sib[q][b]);
                js_match(s,']');
            } else {
                o->ib_se[q][b]=0;
                o->ib_depth[q][b]=parse_sib_list(s,o->ib_sib[q][b]);
            }
        } else js_skip_value(s);
        free(k);
    }
}
static void parse_cp_step(js_t *s, ov_t *o, size_t q, size_t r){
    js_match(s,'{');
    while(!js_match(s,'}')){ if(js_peek(s,',')){s->pos++;continue;} char*k=js_read_string(s); js_match(s,':');
        if(k&&strcmp(k,"log_arity")==0){ uint64_t v=0; js_read_u64(s,&v); if(r<OV_MAXCPC)o->cp_la[q][r]=(uint8_t)v; }
        else if(k&&strcmp(k,"sibling_values")==0){ size_t n=0; js_match(s,'['); while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;} gold_fp2_t fv=parse_fp2_wrapped(s); if(n<4)o->cp_sv[q][r][n]=fv; n++; } o->cp_nsv[q][r]=n; }
        else if(k&&strcmp(k,"opening_proof")==0){
            if(opening_is_salted(s)){
                js_match(s,'[');
                gold_fp_t tmp[OV_MAXM][OV_MAXSE]; size_t se=0;
                (void)parse_salt_list(s,tmp,&se);
                o->cp_se[q][r]=se; for(size_t k2=0;k2<se&&k2<OV_MAXSE;k2++)o->cp_salt[q][r][k2]=tmp[0][k2];
                js_match(s,',');  /* between salts and siblings — parse_sib_list's leading js_match('[') needs the comma gone */
                o->cp_depth[q][r]=parse_sib_list(s,o->cp_sib[q][r]);
                js_match(s,']');
            } else {
                o->cp_se[q][r]=0;
                o->cp_depth[q][r]=parse_sib_list(s,o->cp_sib[q][r]);
            }
        } else js_skip_value(s);
        free(k);
    }
}
static void parse_query_proof(js_t *s, ov_t *o, size_t q){
    js_match(s,'{');
    while(!js_match(s,'}')){ if(js_peek(s,',')){s->pos++;continue;} char*k=js_read_string(s); js_match(s,':');
        if(k&&strcmp(k,"input_proof")==0){ size_t b=0; js_match(s,'['); while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;} if(b<OV_MAXB)parse_input_batch(s,o,q,b); else js_skip_value(s); b++; } }
        else if(k&&strcmp(k,"commit_phase_openings")==0){ size_t r=0; js_match(s,'['); while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;} if(r<OV_MAXCPC)parse_cp_step(s,o,q,r); else js_skip_value(s); r++; } o->cp_nsteps[q]=r; }
        else js_skip_value(s);
        free(k);
    }
}
static void parse_friproof(js_t *s, ov_t *o){
    js_match(s,'{');
    while(!js_match(s,'}')){ if(js_peek(s,',')){s->pos++;continue;} char*k=js_read_string(s); js_match(s,':');
        if(k&&strcmp(k,"commit_phase_commits")==0){ size_t n=0; js_match(s,'['); while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;}
            /* {_marker, cap:[[4]]} */
            dnac_p2_digest_t dg={{0,0,0,0}}; js_match(s,'{');
            while(!js_match(s,'}')){ if(js_peek(s,',')){s->pos++;continue;} char*ck=js_read_string(s); js_match(s,':');
                if(ck&&strcmp(ck,"cap")==0){ js_match(s,'['); if(!js_match(s,']')){ parse_digest_arr(s,&dg); while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;} js_skip_value(s);} } }
                else { js_skip_value(s); }
                free(ck); }
            if(n<OV_MAXCPC){ o->cpc[n]=dg; }
            n++; } o->n_cpc=n; }
        else if(k&&strcmp(k,"commit_pow_witnesses")==0){ size_t n=0; js_match(s,'['); while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;} uint64_t v=parse_base_obj(s); if(n<OV_MAXCPC)o->cpw[n]=gold_fp_from_u64(v); n++; } o->n_cpw=n; }
        else if(k&&strcmp(k,"final_poly")==0){ size_t n=0; js_match(s,'['); while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;} gold_fp2_t fv=parse_fp2_wrapped(s); if(n<OV_MAXFP)o->final_poly[n]=fv; n++; } o->n_fp=n; }
        else if(k&&strcmp(k,"query_pow_witness")==0){ uint64_t v=parse_base_obj(s); o->qpw=gold_fp_from_u64(v); }
        else if(k&&strcmp(k,"query_proofs")==0){ size_t q=0; js_match(s,'['); while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;} if(q<OV_MAXQ)parse_query_proof(s,o,q); else js_skip_value(s); q++; } o->n_q=q; }
        else js_skip_value(s);
        free(k);
    }
}
/* opening_proof = [rand_openings, friproof] (is_zk). rand_openings =
 * [round][mat][point] → each point is a list of codeword fp2's (wrapped). */
static void parse_opening_proof_pair(js_t *s, ov_t *o){
    js_match(s,'[');
    /* element 0: rand_openings */
    size_t e=0; js_match(s,'[');
    while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;}          /* rounds */
        js_match(s,'[');
        while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;}       /* matrices */
            js_match(s,'[');
            while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;}   /* points */
                size_t c=0; js_match(s,'[');
                while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;} gold_fp2_t fv=parse_fp2_wrapped(s); if(e<OV_MAXRO&&c<OV_MAXROV)o->ro_val[e][c]=fv; c++; }
                if(e<OV_MAXRO){ o->ro_len[e]=c; }
                e++;
            }
        }
    }
    o->n_ro=e;
    if(js_peek(s,',')) s->pos++;
    /* element 1: friproof */
    parse_friproof(s,o);
    while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;} js_skip_value(s);}
}
static void parse_opened(js_t *s, ov_t *o){
    js_match(s,'{');
    while(!js_match(s,'}')){ if(js_peek(s,',')){s->pos++;continue;} char*k=js_read_string(s); js_match(s,':');
        if(k&&strcmp(k,"trace_local")==0){ size_t n=0; js_match(s,'['); while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;} gold_fp2_t fv=parse_fp2_decimal(s); if(n<OV_MAXW)o->trace_local[n]=fv; n++; } o->trace_local_len=n; }
        else if(k&&strcmp(k,"trace_next")==0){ size_t n=0; js_match(s,'['); while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;} gold_fp2_t fv=parse_fp2_decimal(s); if(n<OV_MAXW)o->trace_next[n]=fv; n++; } o->trace_next_len=n; }
        else if(k&&strcmp(k,"quotient_chunks")==0){ size_t n=0; js_match(s,'['); while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;} size_t c=0; js_match(s,'['); while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;} gold_fp2_t fv=parse_fp2_decimal(s); if(n<16&&c<2)o->quot_chunks[n][c]=fv; c++; } n++; } o->nqc=n; }
        else if(k&&strcmp(k,"random")==0){ size_t n=0; js_match(s,'['); while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;} gold_fp2_t fv=parse_fp2_decimal(s); if(n<OV_MAXROV)o->random[n]=fv; n++; } o->random_len=n; }
        else if(k&&strcmp(k,"permutation_local")==0){ size_t n=0; js_match(s,'['); while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;} js_skip_value(s); n++; } o->perm_local_len=n; }
        else if(k&&strcmp(k,"permutation_next")==0){ size_t n=0; js_match(s,'['); while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;} js_skip_value(s); n++; } o->perm_next_len=n; }
        else js_skip_value(s);
        free(k);
    }
}
static void parse_commit_str_or_null(js_t *s, int *have, dnac_p2_digest_t *d){
    if(js_peek(s,'"')){ char*h=js_read_string(s); uint8_t b[32]; if(hex_decode(h,b,32)==32){ p2_digest_from_le_bytes(b,d); *have=1; } free(h); }
    else { js_skip_value(s); *have=0; }
}
static void parse_scenario(js_t *s, ov_t *o){
    js_match(s,'{');
    while(!js_match(s,'}')){ if(js_peek(s,',')){s->pos++;continue;} char*k=js_read_string(s); if(!k)break; js_match(s,':');
        if(strcmp(k,"name")==0){ char*v=js_read_string(s); if(v){ strncpy(o->name,v,sizeof o->name-1); free(v);} }
        else if(strcmp(k,"salted")==0){ js_read_u64(s,&o->salted); }
        else if(strcmp(k,"is_zk")==0){ uint64_t v=0; js_read_u64(s,&v); o->is_zk=(int)v; }
        else if(strcmp(k,"degree_bits")==0){ uint64_t v=0; js_match(s,'['); if(!js_match(s,']')){ js_read_u64(s,&v); while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;} js_skip_value(s);} } o->degree_bits=(size_t)v; }
        else if(strcmp(k,"alpha")==0){ o->alpha=parse_fp2_decimal(s); }
        else if(strcmp(k,"zeta")==0){ o->zeta=parse_fp2_decimal(s); }
        else if(strcmp(k,"commits")==0){ js_match(s,'{'); while(!js_match(s,'}')){ if(js_peek(s,',')){s->pos++;continue;} char*ck=js_read_string(s); js_match(s,':');
            if(ck&&strcmp(ck,"main")==0)parse_commit_str_or_null(s,&o->have_main,&o->main_c);
            else if(ck&&strcmp(ck,"quotient")==0)parse_commit_str_or_null(s,&o->have_quot,&o->quot_c);
            else if(ck&&strcmp(ck,"random")==0)parse_commit_str_or_null(s,&o->have_rand,&o->rand_c);
            else if(ck&&strcmp(ck,"preprocessed")==0){ int hv; dnac_p2_digest_t dd; parse_commit_str_or_null(s,&hv,&dd); o->have_prep=hv; }
            else if(ck&&strcmp(ck,"permutation")==0){ int hv; dnac_p2_digest_t dd; parse_commit_str_or_null(s,&hv,&dd); o->have_perm=hv; }
            else { js_skip_value(s); }
            free(ck);} }
        else if(strcmp(k,"instances")==0){ js_match(s,'['); /* 1 instance */
            js_match(s,'{'); while(!js_match(s,'}')){ if(js_peek(s,',')){s->pos++;continue;} char*ik=js_read_string(s); js_match(s,':');
                if(ik&&strcmp(ik,"opened")==0)parse_opened(s,o);
                else if(ik&&strcmp(ik,"public_values")==0){ size_t n=0; js_match(s,'['); while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;} char*v=js_peek(s,'"')?js_read_string(s):NULL; uint64_t pv=0; if(v){pv=strtoull(v,NULL,10);free(v);}else{js_read_u64(s,&pv);} if(n<64)o->pub[n]=pv; n++; } o->n_pub=n; }
                else js_skip_value(s);
                free(ik);}
            while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;} js_skip_value(s);} }
        else if(strcmp(k,"proof_serde")==0){ js_match(s,'{'); while(!js_match(s,'}')){ if(js_peek(s,',')){s->pos++;continue;} char*pk=js_read_string(s); js_match(s,':'); if(pk&&strcmp(pk,"opening_proof")==0)parse_opening_proof_pair(s,o); else js_skip_value(s); free(pk);} }
        else js_skip_value(s);
        free(k);
    }
}

/* ===== aggregate fixture builders (== test_prover_agg.c) ===== */
/* S8 Gate 2: sibling stride is D levels x 4 lanes, sized by the MACRO (D = 24),
 * never a literal 4. */
#define BSA_SIB_STRIDE ((size_t)CONF_AGG_TREE_DEPTH * 4)
typedef struct {
    uint64_t value[5], addr[5*4], rcm[5*2], pos[5], nk[5*4], ak[5*4];
    uint8_t  roles[5];
    uint64_t memb_siblings[5 * CONF_AGG_TREE_DEPTH * 4];
    uint64_t txbind[4];
} agg_fixture_t;

/* kind: 0 = 1in (h=128), 1 = 2in (h=128), 2 = 4in (h=256). Returns log_height,
 * fills inst pointing into fx (must outlive inst). */
static unsigned build_agg_fixture(int kind, agg_fixture_t *fx,
                                  dnac_agg_prover_instance_t *inst){
    memset(fx,0,sizeof *fx);
    size_t num_notes=3; unsigned log_height=7;
    static const uint64_t kat_txbind[4]={0x1111111111111111ULL,0x2222222222222222ULL,
                                         0x3333333333333333ULL,0x4444444444444444ULL};
    memcpy(fx->txbind,kat_txbind,sizeof kat_txbind);
    if(kind==2){
        log_height=8; num_notes=5;
        for(int i=0;i<4;i++){ fx->value[i]=25; fx->roles[i]=CONF_ACTION_ROLE_INPUT; fx->pos[i]=(uint64_t)i; }
        fx->value[4]=100; fx->roles[4]=CONF_ACTION_ROLE_OUTPUT; fx->pos[4]=0;
        const uint64_t k[5*4]={0x22222222ULL,0x22222223ULL,0x22222224ULL,0x22222225ULL,
                               0x33333333ULL,0x33333334ULL,0x33333335ULL,0x33333336ULL,
                               0x44444444ULL,0x44444445ULL,0x44444446ULL,0x44444447ULL,
                               0x55555555ULL,0x55555556ULL,0x55555557ULL,0x55555558ULL,
                               0,0,0,0}; memcpy(fx->nk,k,sizeof k);
        const uint64_t a[5*4]={0x11111111ULL,0x11111112ULL,0x11111113ULL,0x11111114ULL,
                               0x12121212ULL,0x12121213ULL,0x12121214ULL,0x12121215ULL,
                               0x13131313ULL,0x13131314ULL,0x13131315ULL,0x13131316ULL,
                               0x14141414ULL,0x14141415ULL,0x14141416ULL,0x14141417ULL,
                               0,0,0,0}; memcpy(fx->ak,a,sizeof a);
        const uint64_t rc[5*2]={0x11,0x12, 0x13,0x14, 0x15,0x16, 0x17,0x18, 0x21,0x22}; memcpy(fx->rcm,rc,sizeof rc);
        fx->addr[4*4+0]=0xAA01; fx->addr[4*4+1]=0xAA02; fx->addr[4*4+2]=0xAA03; fx->addr[4*4+3]=0xAA04;
        uint64_t cm[4][4], adr[4];
        for(int i=0;i<4;i++){ conf_action_derive_addr(&fx->ak[i*4],&fx->nk[i*4],adr); note_commit(25,adr,&fx->rcm[i*2],cm[i]); }
        uint64_t n01[4], n23[4];
        note_merkle_compress(cm[0],cm[1],n01);
        note_merkle_compress(cm[2],cm[3],n23);
        uint64_t *ms=fx->memb_siblings;
        for(int j=0;j<4;j++){
            ms[0*BSA_SIB_STRIDE+0*4+j]=cm[1][j]; ms[0*BSA_SIB_STRIDE+1*4+j]=n23[j];
            ms[1*BSA_SIB_STRIDE+0*4+j]=cm[0][j]; ms[1*BSA_SIB_STRIDE+1*4+j]=n23[j];
            ms[2*BSA_SIB_STRIDE+0*4+j]=cm[3][j]; ms[2*BSA_SIB_STRIDE+1*4+j]=n01[j];
            ms[3*BSA_SIB_STRIDE+0*4+j]=cm[2][j]; ms[3*BSA_SIB_STRIDE+1*4+j]=n01[j];
        }
        /* Levels 2..D-1: the pre-S8 e2/e3 rule {0x(L+1)001..0x(L+1)004}
         * extended to every level, IDENTICAL across the four blocks so all
         * walks converge on ONE anchor. Levels 2/3 stay byte-identical. */
        for(unsigned L=2;L<(unsigned)CONF_AGG_TREE_DEPTH;L++)
            for(int b=0;b<4;b++)
                for(int j=0;j<4;j++)
                    ms[(size_t)b*BSA_SIB_STRIDE+(size_t)L*4+j]=
                        (uint64_t)0x1000*(L+1)+0x0001+(uint64_t)j;
    } else if(kind==1){
        const uint64_t v[3]={60,40,100};       memcpy(fx->value,v,sizeof v);
        const uint8_t  r[3]={CONF_ACTION_ROLE_INPUT,CONF_ACTION_ROLE_INPUT,CONF_ACTION_ROLE_OUTPUT}; memcpy(fx->roles,r,sizeof r);
        const uint64_t p[3]={0,1,0};           memcpy(fx->pos,p,sizeof p);
        const uint64_t k[3*4]={0x22222222ULL,0x22222223ULL,0x22222224ULL,0x22222225ULL,
                               0x33333333ULL,0x33333334ULL,0x33333335ULL,0x33333336ULL,
                               0,0,0,0}; memcpy(fx->nk,k,sizeof k);
        const uint64_t a[3*4]={0x11111111ULL,0x11111112ULL,0x11111113ULL,0x11111114ULL,
                               0x12121212ULL,0x12121213ULL,0x12121214ULL,0x12121215ULL,
                               0,0,0,0}; memcpy(fx->ak,a,sizeof a);
        const uint64_t ad[3*4]={0,0,0,0, 0,0,0,0, 0xAA01,0xAA02,0xAA03,0xAA04}; memcpy(fx->addr,ad,sizeof ad);
        const uint64_t rc[3*2]={0x11,0x12, 0x13,0x14, 0x21,0x22}; memcpy(fx->rcm,rc,sizeof rc);
        uint64_t addr0[4],addr1[4],cm0[4],cm1[4];
        conf_action_derive_addr(&fx->ak[0],&fx->nk[0],addr0);  note_commit(fx->value[0],addr0,&fx->rcm[0],cm0);
        conf_action_derive_addr(&fx->ak[4],&fx->nk[4],addr1);  note_commit(fx->value[1],addr1,&fx->rcm[2],cm1);
        for(int j=0;j<4;j++){ fx->memb_siblings[0*BSA_SIB_STRIDE+0*4+j]=cm1[j]; fx->memb_siblings[1*BSA_SIB_STRIDE+0*4+j]=cm0[j]; }
        /* Levels 1..D-1 share ONE filler per level (the pre-S8 `up` rule
         * {0x(L+1)001..0x(L+1)004} extended from 3 levels to D-1) so both walks
         * reach the SAME anchor. Levels 1-3 stay byte-identical. */
        for(unsigned L=1;L<(unsigned)CONF_AGG_TREE_DEPTH;L++)
            for(int j=0;j<4;j++){
                const uint64_t f=(uint64_t)0x1000*(L+1)+0x0001+(uint64_t)j;
                fx->memb_siblings[0*BSA_SIB_STRIDE+(size_t)L*4+j]=f;
                fx->memb_siblings[1*BSA_SIB_STRIDE+(size_t)L*4+j]=f;
            }
    } else {
        /* ⚠ S8 Gate 2: note 2 WAS a CONF_ACTION_ROLE_FEE block. IS_FEE is pinned
         * ZERO and generate rejects a FEE-role note, so it is now a second
         * OUTPUT of the SAME value (the set stays conserving); the fee reaches
         * the statement as the independent public inst->fee, set below. */
        const uint64_t v[3]={100,70,30};       memcpy(fx->value,v,sizeof v);
        const uint8_t  r[3]={CONF_ACTION_ROLE_INPUT,CONF_ACTION_ROLE_OUTPUT,CONF_ACTION_ROLE_OUTPUT}; memcpy(fx->roles,r,sizeof r);
        const uint64_t p[3]={5,0,0};           memcpy(fx->pos,p,sizeof p);
        const uint64_t k[3*4]={0x22222222ULL,0x22222223ULL,0x22222224ULL,0x22222225ULL,
                               0,0,0,0, 0,0,0,0}; memcpy(fx->nk,k,sizeof k);
        const uint64_t a[3*4]={0x11111111ULL,0x11111112ULL,0x11111113ULL,0x11111114ULL,
                               0,0,0,0, 0,0,0,0}; memcpy(fx->ak,a,sizeof a);
        const uint64_t ad[3*4]={0,0,0,0, 0xAA01,0xAA02,0xAA03,0xAA04, 0xFEE1,0xFEE2,0xFEE3,0xFEE4}; memcpy(fx->addr,ad,sizeof ad);
        const uint64_t rc[3*2]={0x11,0x12, 0x21,0x22, 0x31,0x32}; memcpy(fx->rcm,rc,sizeof rc);
        /* Block 0 (the only INPUT) walks D levels; the pre-S8 fixture spelled
         * out 4 literal levels {0x(L+1)001..0x(L+1)004} — the SAME rule now
         * fills all D, so levels 0-3 stay byte-identical. Blocks 1/2 are
         * OUTPUTs: their sibling slots are never read. */
        for(unsigned L=0;L<(unsigned)CONF_AGG_TREE_DEPTH;L++)
            for(int j=0;j<4;j++)
                fx->memb_siblings[0*BSA_SIB_STRIDE+(size_t)L*4+j]=
                    (uint64_t)0x1000*(L+1)+0x0001+(uint64_t)j;
    }
    memset(inst,0,sizeof *inst);
    inst->value=fx->value; inst->addr=fx->addr; inst->rcm=fx->rcm; inst->roles=fx->roles;
    inst->pos=fx->pos; inst->nk=fx->nk; inst->ak=fx->ak; inst->num_notes=num_notes;
    inst->memb_siblings=fx->memb_siblings; inst->tx_binding=fx->txbind;
    inst->log_height=log_height;
    /* S8 Gate 2 turnstile + fee: these three are PUBLICS with no in-circuit
     * derivation left (the fee stopped being a FEE-role note's value when
     * IS_FEE was pinned zero, and the boundary legs are pure publics), so the
     * fixture MUST NOT invent them — a hard-coded guess silently diverges from
     * the pinned KAT and shows up as an opaque "computed publics != oracle"
     * cascade. The caller binds all three FROM the parsed vector immediately
     * after this returns; leave them zeroed here (memset above). */
    return log_height;
}

/* ===== comparators ===== */
static int g_checks=0, g_fails=0;
#define CHK(cond,...) do{ g_checks++; if(!(cond)){ g_fails++; fprintf(stderr,"  FAIL: "); fprintf(stderr,__VA_ARGS__); fprintf(stderr,"\n"); } }while(0)
static int fp2_eq(gold_fp2_t a, gold_fp2_t b){ return gold_fp_to_u64(a.a)==gold_fp_to_u64(b.a)&&gold_fp_to_u64(a.b)==gold_fp_to_u64(b.b); }
static int fp_eq(gold_fp_t a, gold_fp_t b){ return gold_fp_to_u64(a)==gold_fp_to_u64(b); }
static int dig_eq(const dnac_p2_digest_t*a,const dnac_p2_digest_t*b){ for(int k=0;k<4;k++) if(a->lanes[k]!=b->lanes[k])return 0; return 1; }
static int lanes_dig_eq(const gold_fp_t*lanes,const dnac_p2_digest_t*d){ for(int k=0;k<4;k++) if(gold_fp_to_u64(lanes[k])!=d->lanes[k])return 0; return 1; }

/* draw-stream loader (== test_prover_agg): read the smallrng "draws" array. */
static uint64_t *g_draws=NULL; static size_t g_ndraws=0;
static int load_draws(const char *path){
    size_t bl=0; char *blob=slurp(path,&bl); if(!blob)return 0;
    js_t s={blob,0,bl}; js_match(&s,'{'); size_t cap=1<<20, n=0;
    uint64_t *buf=(uint64_t*)malloc(cap*sizeof(uint64_t)); if(!buf){ free(blob); return 0; }
    while(!js_match(&s,'}')){ if(js_peek(&s,',')){s.pos++;continue;} char*k=js_read_string(&s); if(!k)break; js_match(&s,':');
        if(strcmp(k,"draws")==0){ js_match(&s,'['); while(!js_match(&s,']')){ if(js_peek(&s,',')){s.pos++;continue;} char*v=js_read_string(&s); if(v){ if(n>=cap){ cap*=2; buf=(uint64_t*)realloc(buf,cap*sizeof(uint64_t)); } buf[n++]=strtoull(v,NULL,10); free(v);} else js_skip_value(&s); } }
        else js_skip_value(&s);
        free(k);
    }
    free(blob); g_draws=buf; g_ndraws=n; return 1;
}

static void match_scenario(const ov_t *o, const dnac_batch_proof_t *p){
    const char *nm=o->name;
    /* commits */
    dnac_batch_vcommits_t cm; dnac_batch_proof_commits(p,&cm);
    CHK((cm.main_commit!=NULL)==(o->have_main!=0),"%s: main presence",nm);
    CHK((cm.quotient_commit!=NULL)==(o->have_quot!=0),"%s: quot presence",nm);
    CHK((cm.random_commit!=NULL)==(o->have_rand!=0),"%s: random presence",nm);
    CHK((cm.preprocessed_commit!=NULL)==(o->have_prep!=0),"%s: prep presence",nm);
    CHK((cm.permutation_commit!=NULL)==(o->have_perm!=0),"%s: perm presence",nm);
    if(cm.main_commit&&o->have_main) CHK(lanes_dig_eq(cm.main_commit,&o->main_c),"%s: main root MISMATCH",nm);
    if(cm.quotient_commit&&o->have_quot) CHK(lanes_dig_eq(cm.quotient_commit,&o->quot_c),"%s: quot root MISMATCH",nm);
    if(cm.random_commit&&o->have_rand) CHK(lanes_dig_eq(cm.random_commit,&o->rand_c),"%s: random root MISMATCH",nm);

    /* alpha / zeta */
    gold_fp2_t alpha,zeta; dnac_batch_proof_alpha_zeta(p,&alpha,&zeta);
    CHK(fp2_eq(alpha,o->alpha),"%s: alpha MISMATCH",nm);
    CHK(fp2_eq(zeta,o->zeta),"%s: zeta MISMATCH",nm);

    /* opened (instance 0) */
    const dnac_batch_vopened_t *oi=dnac_batch_proof_opened(p,0);
    CHK(oi->trace_local_len==o->trace_local_len,"%s: trace_local len %u!=%zu",nm,oi->trace_local_len,o->trace_local_len);
    { int ok=oi->trace_local_len==o->trace_local_len; for(uint32_t k=0;ok&&k<oi->trace_local_len;k++) if(!fp2_eq(oi->trace_local[k],o->trace_local[k]))ok=0; CHK(ok,"%s: trace_local values",nm); }
    CHK(oi->trace_next_len==o->trace_next_len,"%s: trace_next len %u!=%zu",nm,oi->trace_next_len,o->trace_next_len);
    { int ok=oi->trace_next_len==o->trace_next_len; for(uint32_t k=0;ok&&k<oi->trace_next_len;k++) if(!fp2_eq(oi->trace_next[k],o->trace_next[k]))ok=0; CHK(ok,"%s: trace_next values",nm); }
    CHK(oi->num_quotient_chunks==o->nqc,"%s: nqc %u!=%zu",nm,oi->num_quotient_chunks,o->nqc);
    { int ok=oi->num_quotient_chunks==o->nqc; for(size_t c=0;ok&&c<o->nqc;c++){ if(!fp2_eq(oi->quotient_chunks[2*c],o->quot_chunks[c][0])||!fp2_eq(oi->quotient_chunks[2*c+1],o->quot_chunks[c][1]))ok=0; } CHK(ok,"%s: quotient chunk values",nm); }
    CHK(oi->random_len==o->random_len,"%s: random len %u!=%zu",nm,oi->random_len,o->random_len);
    { int ok=oi->random_len==o->random_len; for(uint32_t k=0;ok&&k<oi->random_len;k++) if(!fp2_eq(oi->random[k],o->random[k]))ok=0; CHK(ok,"%s: random values",nm); }
    CHK(oi->permutation_len==0 && o->perm_local_len==0 && o->perm_next_len==0,"%s: permutation empty",nm);

    /* FRI proof */
    const dnac_fri_proof_t *gp=dnac_batch_proof_fri(p);
    CHK(gp->num_commit_phase_commits==o->n_cpc,"%s: cpc count %zu!=%zu",nm,gp->num_commit_phase_commits,o->n_cpc);
    { int ok=gp->num_commit_phase_commits==o->n_cpc; for(size_t r=0;ok&&r<o->n_cpc;r++) if(!dig_eq(&gp->commit_phase_commits[r],&o->cpc[r]))ok=0; CHK(ok,"%s: cpc values",nm); }
    { int ok=gp->num_commit_pow_witnesses==o->n_cpw; for(size_t r=0;ok&&r<o->n_cpw;r++) if(!fp_eq(gp->commit_pow_witnesses[r],o->cpw[r]))ok=0; CHK(ok,"%s: cpw",nm); }
    CHK(gp->num_final_poly==o->n_fp,"%s: final_poly len %zu!=%zu",nm,gp->num_final_poly,o->n_fp);
    { int ok=gp->num_final_poly==o->n_fp; for(size_t k=0;ok&&k<o->n_fp;k++) if(!fp2_eq(gp->final_poly[k],o->final_poly[k]))ok=0; CHK(ok,"%s: final_poly values",nm); }
    CHK(fp_eq(gp->query_pow_witness,o->qpw),"%s: qpw",nm);
    CHK(gp->num_query_proofs==o->n_q,"%s: query count %zu!=%zu",nm,gp->num_query_proofs,o->n_q);

    for(size_t q=0;q<gp->num_query_proofs&&q<o->n_q;q++){
        const dnac_fri_query_proof_t *gq=&gp->query_proofs[q];
        CHK(gq->num_input_batches==3,"%s: q%zu input batch count %zu",nm,q,gq->num_input_batches);
        for(size_t b=0;b<gq->num_input_batches&&b<OV_MAXB;b++){
            const dnac_fri_batch_opening_t *gb=&gq->input_proof[b];
            CHK(gb->num_matrices==o->ib_nmat[q][b],"%s: q%zu b%zu nmat %zu!=%zu",nm,q,b,gb->num_matrices,o->ib_nmat[q][b]);
            int ok=gb->num_matrices==o->ib_nmat[q][b];
            for(size_t m=0;ok&&m<gb->num_matrices;m++){
                if(gb->opened_values_lens[m]!=o->ib_w[q][b][m]){ ok=0; break; }
                for(size_t c=0;c<gb->opened_values_lens[m];c++) if(gold_fp_to_u64(gb->opened_values[m][c])!=gold_fp_to_u64(o->ib_ov[q][b][m][c])){ ok=0; break; }
            }
            CHK(ok,"%s: q%zu b%zu opened rows",nm,q,b);
            CHK(gb->opening_proof.depth==o->ib_depth[q][b],"%s: q%zu b%zu depth %u!=%zu",nm,q,b,gb->opening_proof.depth,o->ib_depth[q][b]);
            { int sok=gb->opening_proof.depth==o->ib_depth[q][b]; for(size_t sdx=0;sok&&sdx<o->ib_depth[q][b];sdx++) if(!dig_eq(&gb->opening_proof.siblings[sdx],&o->ib_sib[q][b][sdx]))sok=0; CHK(sok,"%s: q%zu b%zu siblings",nm,q,b); }
            /* salts */
            CHK(gb->salt_elems==o->ib_se[q][b],"%s: q%zu b%zu salt_elems %zu!=%zu",nm,q,b,gb->salt_elems,o->ib_se[q][b]);
            if(o->ib_se[q][b]>0){
                int sok=gb->salts!=NULL && gb->salt_elems==o->ib_se[q][b];
                for(size_t m=0;sok&&m<o->ib_nmat[q][b];m++){ for(size_t se=0;se<o->ib_se[q][b];se++) if(gold_fp_to_u64(gb->salts[m][se])!=gold_fp_to_u64(o->ib_salt[q][b][m][se])){ sok=0; break; } }
                CHK(sok,"%s: q%zu b%zu SALTS",nm,q,b);
            } else {
                CHK(gb->salts==NULL,"%s: q%zu b%zu salts NULL (plain)",nm,q,b);
            }
        }
        CHK(gq->num_commit_phase_openings==o->cp_nsteps[q],"%s: q%zu cp steps %zu!=%zu",nm,q,gq->num_commit_phase_openings,o->cp_nsteps[q]);
        for(size_t r=0;r<gq->num_commit_phase_openings&&r<o->cp_nsteps[q]&&r<OV_MAXCPC;r++){
            const dnac_fri_commit_phase_proof_step_t *gs=&gq->commit_phase_openings[r];
            int ok=gs->log_arity==o->cp_la[q][r] && gs->num_sibling_values==o->cp_nsv[q][r] && gs->opening_proof.depth==o->cp_depth[q][r];
            for(size_t sv=0;ok&&sv<gs->num_sibling_values;sv++) if(!fp2_eq(gs->sibling_values[sv],o->cp_sv[q][r][sv]))ok=0;
            for(size_t sdx=0;ok&&sdx<gs->opening_proof.depth;sdx++) if(!dig_eq(&gs->opening_proof.siblings[sdx],&o->cp_sib[q][r][sdx]))ok=0;
            CHK(ok,"%s: q%zu cp step %zu",nm,q,r);
            CHK(gs->salt_elems==o->cp_se[q][r],"%s: q%zu cp %zu salt_elems %zu!=%zu",nm,q,r,gs->salt_elems,o->cp_se[q][r]);
            if(o->cp_se[q][r]>0){ int sok=gs->salts!=NULL; for(size_t se=0;sok&&se<o->cp_se[q][r];se++) if(gold_fp_to_u64(gs->salts[se])!=gold_fp_to_u64(o->cp_salt[q][r][se]))sok=0; CHK(sok,"%s: q%zu cp %zu SALTS",nm,q,r); }
            else CHK(gs->salts==NULL,"%s: q%zu cp %zu salts NULL (plain)",nm,q,r);
        }
    }

    /* rand openings */
    const dnac_batch_rand_openings_t *ro=dnac_batch_proof_rand_openings(p);
    CHK(ro!=NULL && ro->num_entries==o->n_ro,"%s: rand-openings entries %u!=%zu",nm,ro?ro->num_entries:0,o->n_ro);
    if(ro && ro->num_entries==o->n_ro){ int ok=1; for(uint32_t e=0;ok&&e<ro->num_entries;e++){ if(ro->lens[e]!=o->ro_len[e]){ ok=0; break; } for(uint32_t c=0;c<ro->lens[e];c++) if(!fp2_eq(ro->vals[e][c],o->ro_val[e][c]))ok=0; } CHK(ok,"%s: rand-openings values",nm); }
}

int main(int argc,char **argv){
    const char *vec = argc>=2 ? argv[1] : "tools/vectors/batch_shielded_agg.json";
    const char *rng = argc>=3 ? argv[2] : "tools/vectors/smallrng_goldilocks.json";

    if(!load_draws(rng)){ fprintf(stderr,"cannot load draws %s\n",rng); return 2; }
    printf("loaded %s (%zu draws)\n",rng,g_ndraws);

    size_t blen=0; char *buf=slurp(vec,&blen);
    if(!buf){ fprintf(stderr,"cannot load %s\n",vec); return 2; }
    printf("loaded %s (%zu bytes)\n",vec,blen);

    js_t s={buf,0,blen}; js_match(&s,'{');
    /* find "scenarios": [ ... ] */
    int found=0;
    while(!js_match(&s,'}')){ if(js_peek(&s,',')){s.pos++;continue;} char*k=js_read_string(&s); if(!k)break; js_match(&s,':');
        if(strcmp(k,"scenarios")==0){ found=1; free(k); break; } js_skip_value(&s); free(k); }
    if(!found){ fprintf(stderr,"no scenarios\n"); free(buf); return 2; }

    js_match(&s,'[');
    size_t nscen=0;
    while(!js_match(&s,']')){
        if(js_peek(&s,',')){s.pos++;continue;}
        ov_t *o=(ov_t*)calloc(1,sizeof *o); if(!o){ fprintf(stderr,"OOM ov\n"); return 2; }
        parse_scenario(&s,o);
        nscen++;

        int kind = strstr(o->name,"4in")?2 : strstr(o->name,"2in")?1 : 0;
        agg_fixture_t fx;
        dnac_agg_prover_instance_t inst;
        unsigned log_height=build_agg_fixture(kind,&fx,&inst);
        /* R1 (S8 Gate 2): bind the three non-derivable publics FROM the pinned
         * KAT rather than hard-coding them in the fixture. fee is FS/sighash-
         * bound only after the IS_FEE zero-pin, and the two turnstile legs are
         * publics the prover is simply TOLD — so the vector is their single
         * source of truth here. Any future fixture/KAT drift then surfaces on
         * the publics equality check below, at the exact index, instead of as
         * an unexplained byte-match cascade. */
        CHK(o->n_pub==CONF_AGGZK_NUM_PUBLICS,
            "%s: oracle publics %zu != %d",o->name,o->n_pub,
            (int)CONF_AGGZK_NUM_PUBLICS);
        inst.fee          = o->pub[CONF_AGGZK_PUB_FEE];
        inst.boundary_in  = o->pub[CONF_AGGZK_PUB_BIN];
        inst.boundary_out = o->pub[CONF_AGGZK_PUB_BOUT];
        const size_t height=(size_t)1<<log_height;

        uint64_t *trace=(uint64_t*)malloc(height*CONF_AGGZK_WIDTH*sizeof(uint64_t));
        /* pubs MUST be zeroed: agg_zk_generate only writes the USED output_commit
         * / nf slots (num_output/num_input); the production prover's publics live
         * in a calloc'd struct so unused slots are 0. malloc here would leave
         * garbage that diverges the publics -> alpha -> the whole proof. */
        gold_fp_t *pubs=(gold_fp_t*)calloc(CONF_AGGZK_NUM_PUBLICS,sizeof(gold_fp_t));
        if(!trace||!pubs){ fprintf(stderr,"OOM trace\n"); return 2; }
        if(!dnac_agg_zk_generate_trace_testonly(log_height,&inst,trace,pubs)){
            CHK(0,"%s: agg_zk_generate failed",o->name); free(trace); free(pubs); free(o); continue;
        }

        dnac_batch_vinstance_t vi; memset(&vi,0,sizeof vi);
        vi.air = DNAC_CONF_ACTION_AGG_FOLD_AIR;
        vi.preprocessed_width=0; vi.prep_next=0;
        vi.pool=NULL; vi.pool_len=0; vi.lookups=NULL; vi.num_lookups=0;
        vi.degree_bits=(uint32_t)(log_height+1);
        vi.log_num_qc=2;
        vi.public_values=pubs; vi.num_publics=CONF_AGGZK_NUM_PUBLICS;
        dnac_batch_pwitness_t wi; wi.main_trace=trace; wi.prep_trace=NULL;

        const int salted = (o->salted!=0);
        dnac_fri_params_t params; memset(&params,0,sizeof params);
        params.log_blowup=2; params.log_final_poly_len=2; params.max_log_arity=1;
        params.num_queries=2; params.commit_proof_of_work_bits=0; params.query_proof_of_work_bits=0;

        size_t nd=dnac_batch_prove_num_draws(&vi,1,1,4);
        size_t ns=salted?dnac_batch_prove_num_salt_draws(&vi,1,1,2,2):0;
        CHK(nd!=(size_t)-1 && nd>0,"%s: nd derivation",o->name);
        if(salted) CHK(ns!=(size_t)-1 && ns>0,"%s: ns derivation",o->name);
        size_t need = nd>ns?nd:ns;
        if(g_ndraws<need){ CHK(0,"%s: draw stream too short %zu<%zu",o->name,g_ndraws,need); free(trace); free(pubs); free(o); continue; }

        /* publics sanity: agg_zk_generate must reproduce the oracle's
         * CONF_AGGZK_NUM_PUBLICS publics (anchor / num_in / nf_slots /
         * num_out / output_commit / fee / boundary_in / boundary_out /
         * tx_binding) exactly — a divergence here would shift alpha and fail
         * the whole byte-match. */
        { int pm=(o->n_pub==CONF_AGGZK_NUM_PUBLICS);
          for(size_t i=0;i<o->n_pub&&i<CONF_AGGZK_NUM_PUBLICS;i++) if(gold_fp_to_u64(pubs[i])!=o->pub[i]) pm=0;
          CHK(pm,"%s: computed publics != oracle public_values",o->name); }
        dnac_batch_proof_t *proof=NULL;
        dnac_prover_status_t st=dnac_batch_prove(
            &vi,&wi,1,1,&params,4,
            g_draws,nd,
            salted?g_draws:NULL, salted?ns:0,
            NULL,0,
            salted?2:0,
            &proof);
        CHK(st==DNAC_PROVER_OK,"%s: dnac_batch_prove -> %d (salted=%d)",o->name,(int)st,salted);
        if(st==DNAC_PROVER_OK){
            match_scenario(o,proof);
            printf("  %-16s kind=%d h=%zu salted=%d db=%zu -> proved + byte-matched\n",
                   o->name,kind,height,salted,o->degree_bits);
            dnac_batch_proof_free(proof);
        }
        free(trace); free(pubs); free(o);
    }

    free(buf); free(g_draws);
    printf("\nbatch_shielded_agg scenarios %18zu\n",nscen);
    printf("batch_shielded_agg total     %18d checks\n",g_checks);
    printf("batch_shielded_agg failed    %18d\n",g_fails);
    if(g_fails==0 && nscen==5){ printf("\nP2L-d d4.c-1 SALTED BATCH PROVER GATE: GREEN\n"); return 0; }
    fprintf(stderr,"\nP2L-d d4.c-1 SALTED BATCH PROVER GATE: RED\n");
    return 1;
}
