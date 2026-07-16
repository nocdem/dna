/**
 * @file test_conf_action_verify.c
 * @brief Dual-mode S1e.3 — C fold-layer vs the REAL Plonky3 verifier on the
 *        C1 Action AIR (width 813, is_zk=1, num_qc=8), 82cfad73.
 *
 * Consumes tools/vectors/conf_action_air_zk.json (a REAL p3_uni_stark is_zk=1
 * proof of ConfActionAir). The gate proves the C fp2 fold
 * (dnac_conf_action_fold_air_eval) reproduces the constraint polynomial the
 * REAL prover committed — pinning both constraint CONTENT and EMISSION ORDER.
 *
 * Gates:
 *   T1  shape: num_qc == 1<<(log_num_qc+1) == 8, log_num_qc==2, publics==0.
 *   T6  folded * inv_vanishing == quotient(zeta): the combined air_eval fold,
 *       driven by the REAL opened values, verifies OK.
 *   T7  negatives: tampered trace cell -> OOD; wrong publics count -> SHAPE;
 *       missing trace_next (main_next=1) -> SHAPE.
 *
 * (T2-T5 — recompose selectors/domains — are AIR-independent and already gated
 * by test_conf_root_verify.c; not duplicated here.)
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "conf_action_fold.h"
#include "field_goldilocks.h"
#include "stark_constraints.h"

/* ===== JSON scanner (test-local convention; as in test_conf_root_verify.c) ===== */
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
static gold_fp2_t parse_fp2_decimal(js_t *s){
    uint64_t c0=0,c1=0; js_match(s,'{');
    while(!js_match(s,'}')){ if(js_peek(s,',')){s->pos++;continue;} char*k=js_read_string(s); js_match(s,':'); char*v=js_peek(s,'"')?js_read_string(s):NULL;
        if(v&&k&&strcmp(k,"c0_decimal")==0)c0=strtoull(v,NULL,10); else if(v&&k&&strcmp(k,"c1_decimal")==0)c1=strtoull(v,NULL,10); else if(!v)js_skip_value(s); free(v); free(k); }
    return gold_fp2_new(gold_fp_from_u64(c0),gold_fp_from_u64(c1));
}
static size_t parse_fp2_decimal_array(js_t *s,gold_fp2_t *out,size_t cap){
    size_t n=0; js_match(s,'[');
    while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;} gold_fp2_t f=parse_fp2_decimal(s); if(n<cap)out[n]=f; n++; }
    return n;
}

/* ===== fixture (CV_W covers the 813 + 4 random merged width) ===== */
#define CV_W 832
#define CV_QC 8
#define CV_PUB 8

typedef struct {
    size_t degree_bits, num_quotient_chunks;
    gold_fp2_t alpha, zeta, zeta_next;
    size_t log_num_qc;
    gold_fp2_t sel_invvan, quotient_zeta;
    gold_fp2_t trace_local[CV_W]; size_t trace_local_len;
    gold_fp2_t trace_next[CV_W];  size_t trace_next_len;
    gold_fp2_t quot_chunk[CV_QC][CV_W]; size_t quot_chunk_len[CV_QC]; size_t num_quot_chunks_parsed;
    gold_fp_t public_values[CV_PUB]; size_t num_public_values;
} cv_t;

static void parse_instance(js_t *s,cv_t *fx){
    js_match(s,'{'); while(!js_match(s,'}')){ if(js_peek(s,',')){s->pos++;continue;} char*k=js_read_string(s); js_match(s,':'); uint64_t v=0; js_read_u64(s,&v);
        if(k&&strcmp(k,"degree_bits")==0)fx->degree_bits=(size_t)v; else if(k&&strcmp(k,"num_quotient_chunks")==0)fx->num_quotient_chunks=(size_t)v; free(k); }
}
static void parse_challenges(js_t *s,cv_t *fx){
    js_match(s,'{'); while(!js_match(s,'}')){ if(js_peek(s,',')){s->pos++;continue;} char*k=js_read_string(s); js_match(s,':');
        if(k&&strcmp(k,"stark_alpha_fp2")==0)fx->alpha=parse_fp2_decimal(s); else if(k&&strcmp(k,"zeta_fp2")==0)fx->zeta=parse_fp2_decimal(s); else if(k&&strcmp(k,"zeta_next_fp2")==0)fx->zeta_next=parse_fp2_decimal(s); else { js_skip_value(s); } free(k); }
}
static void parse_constraint_check(js_t *s,cv_t *fx){
    js_match(s,'{'); while(!js_match(s,'}')){ if(js_peek(s,',')){s->pos++;continue;} char*k=js_read_string(s); js_match(s,':');
        if(k&&strcmp(k,"log_num_quotient_chunks")==0){ uint64_t v=0; js_read_u64(s,&v); fx->log_num_qc=(size_t)v; }
        else if(k&&strcmp(k,"selectors_at_zeta")==0){
            js_match(s,'{'); while(!js_match(s,'}')){ if(js_peek(s,',')){s->pos++;continue;} char*sk=js_read_string(s); js_match(s,':');
                if(sk&&strcmp(sk,"inv_vanishing")==0)fx->sel_invvan=parse_fp2_decimal(s);
                else js_skip_value(s);
                free(sk); }
        }
        else if(k&&strcmp(k,"quotient_zeta_fp2")==0)fx->quotient_zeta=parse_fp2_decimal(s);
        else js_skip_value(s);
        free(k); }
}
static void parse_opened(js_t *s,cv_t *fx){
    js_match(s,'{'); while(!js_match(s,'}')){ if(js_peek(s,',')){s->pos++;continue;} char*k=js_read_string(s); js_match(s,':');
        if(k&&strcmp(k,"trace_local")==0)fx->trace_local_len=parse_fp2_decimal_array(s,fx->trace_local,CV_W);
        else if(k&&strcmp(k,"trace_next")==0){ if(js_peek(s,'['))fx->trace_next_len=parse_fp2_decimal_array(s,fx->trace_next,CV_W); else js_skip_value(s); }
        else if(k&&strcmp(k,"quotient_chunks")==0){ size_t c=0; js_match(s,'['); while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;} if(c<CV_QC)fx->quot_chunk_len[c]=parse_fp2_decimal_array(s,fx->quot_chunk[c],CV_W); else js_skip_value(s); c++; } fx->num_quot_chunks_parsed=c; }
        else { js_skip_value(s); } free(k); }
}
static void parse_public_values(js_t *s,cv_t *fx){
    size_t n=0; js_match(s,'['); while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;} char*v=js_read_string(s); if(v&&n<CV_PUB)fx->public_values[n]=gold_fp_from_u64(strtoull(v,NULL,10)); free(v); n++; } fx->num_public_values=n;
}

static int fp2eq(gold_fp2_t a, gold_fp2_t b){ return gold_fp2_eq(a,b); }

int main(int argc,char **argv){
    if(argc<2){ fprintf(stderr,"usage: %s <conf_action_air_zk.json>\n",argv[0]); return 2; }
    cv_t *fx=(cv_t*)calloc(1,sizeof *fx); if(!fx)return 2;
    size_t bl=0; char *blob=slurp(argv[1],&bl); if(!blob){ fprintf(stderr,"cannot read %s\n",argv[1]); free(fx); return 2; }
    js_t s={blob,0,bl}; js_match(&s,'{');
    while(!js_match(&s,'}')){ if(js_peek(&s,',')){s.pos++;continue;} char*k=js_read_string(&s); if(!k)break; js_match(&s,':');
        if(strcmp(k,"instance")==0)parse_instance(&s,fx);
        else if(strcmp(k,"challenges")==0)parse_challenges(&s,fx);
        else if(strcmp(k,"constraint_check")==0)parse_constraint_check(&s,fx);
        else if(strcmp(k,"opened_values")==0)parse_opened(&s,fx);
        else if(strcmp(k,"public_values")==0)parse_public_values(&s,fx);
        else js_skip_value(&s);
        free(k);
    }
    free(blob);

    const size_t is_zk=1;
    const size_t W=CONF_ACTION_WIDTH;
    int fails=0;

    printf("test_conf_action_verify: C1 Action AIR fold vs REAL is_zk=1 proof\n");

    /* T1 — shape consistency. */
    {
        int ok = fx->num_quotient_chunks==CV_QC
              && fx->log_num_qc==2
              && fx->num_quotient_chunks==((size_t)1<<(fx->log_num_qc+is_zk))
              && fx->num_quot_chunks_parsed==fx->num_quotient_chunks
              && fx->num_public_values==0;
        printf("  T1 shape: num_qc=8, log_num_qc=2, publics=0            %s\n", ok?"PASS":"FAIL");
        if(!ok){ printf("     (num_qc=%zu log_num_qc=%zu publics=%zu)\n",fx->num_quotient_chunks,fx->log_num_qc,fx->num_public_values); fails++; }
    }

    /* Build the merged->flat quotient chunk buffer once (stride = chunk width). */
    gold_fp2_t *flat=(gold_fp2_t*)calloc(CV_QC*CV_W,sizeof *flat);
    size_t stride=fx->quot_chunk_len[0];
    for(size_t cc=0;cc<CV_QC;cc++)
        for(size_t j=0;j<stride&&j<CV_W;j++)
            flat[cc*stride+j]=fx->quot_chunk[cc][j];

    /* T6 — the fold gate: folded * inv_vanishing == quotient(zeta). The trace
     * vectors are the merged (base ++ 4 random) opened values; the constraint
     * layer consumes the UNMERGED first 813 (hiding_pcs split = len - 4). */
    {
        int ok = fx->trace_local_len==W+4 && fx->trace_next_len==W+4;
        dnac_stark_verify_status_t st = dnac_stark_verify_constraints_nchunk(
            &DNAC_CONF_ACTION_FOLD_AIR,
            fx->trace_local, W, fx->trace_next, W,
            fx->public_values, fx->num_public_values,
            fx->zeta, fx->degree_bits, fx->log_num_qc, is_zk,
            fx->alpha, flat, CV_QC, stride);
        ok = ok && (st==DNAC_STARK_VERIFY_OK);
        printf("  T6 combined air_eval fold: verify_constraints==OK      %s\n", ok?"PASS":"FAIL");
        if(!ok){ printf("     (status=%d local_len=%zu next_len=%zu)\n",(int)st,fx->trace_local_len,fx->trace_next_len); fails++; }
    }

    /* T7 — negatives through the FULL constraint check. */
    {
        int neg=1;
        #define RUN_NCHUNK() dnac_stark_verify_constraints_nchunk( \
            &DNAC_CONF_ACTION_FOLD_AIR, fx->trace_local, W, fx->trace_next, W, \
            fx->public_values, fx->num_public_values, fx->zeta, fx->degree_bits, \
            fx->log_num_qc, is_zk, fx->alpha, flat, CV_QC, stride)
        /* (a) tampered phi cell -> OOD */
        fx->trace_local[CONF_ACTION_PHI_OFF]=gold_fp2_add(fx->trace_local[CONF_ACTION_PHI_OFF],gold_fp2_one());
        if(RUN_NCHUNK()!=DNAC_STARK_VERIFY_ERR_OOD_MISMATCH)neg=0;
        fx->trace_local[CONF_ACTION_PHI_OFF]=gold_fp2_sub(fx->trace_local[CONF_ACTION_PHI_OFF],gold_fp2_one());
        /* (b) tampered BAL cell -> OOD (balance conservation teeth) */
        fx->trace_local[CONF_ACTION_BAL_OFF]=gold_fp2_add(fx->trace_local[CONF_ACTION_BAL_OFF],gold_fp2_one());
        if(RUN_NCHUNK()!=DNAC_STARK_VERIFY_ERR_OOD_MISMATCH)neg=0;
        fx->trace_local[CONF_ACTION_BAL_OFF]=gold_fp2_sub(fx->trace_local[CONF_ACTION_BAL_OFF],gold_fp2_one());
        /* (c) tampered committed ADDR cell -> OOD (spend-auth / note-commit teeth) */
        fx->trace_local[CONF_ACTION_ADDR_OFF]=gold_fp2_add(fx->trace_local[CONF_ACTION_ADDR_OFF],gold_fp2_one());
        if(RUN_NCHUNK()!=DNAC_STARK_VERIFY_ERR_OOD_MISMATCH)neg=0;
        fx->trace_local[CONF_ACTION_ADDR_OFF]=gold_fp2_sub(fx->trace_local[CONF_ACTION_ADDR_OFF],gold_fp2_one());
        /* (d) wrong publics count (1 != 0) -> SHAPE */
        if(dnac_stark_verify_constraints_nchunk(&DNAC_CONF_ACTION_FOLD_AIR,
            fx->trace_local,W,fx->trace_next,W,fx->public_values,1,
            fx->zeta,fx->degree_bits,fx->log_num_qc,is_zk,fx->alpha,flat,CV_QC,stride)
            !=DNAC_STARK_VERIFY_ERR_SHAPE)neg=0;
        /* (e) missing trace_next (main_next=1) -> SHAPE */
        if(dnac_stark_verify_constraints_nchunk(&DNAC_CONF_ACTION_FOLD_AIR,
            fx->trace_local,W,NULL,0,fx->public_values,fx->num_public_values,
            fx->zeta,fx->degree_bits,fx->log_num_qc,is_zk,fx->alpha,flat,CV_QC,stride)
            !=DNAC_STARK_VERIFY_ERR_SHAPE)neg=0;
        #undef RUN_NCHUNK
        printf("  T7 negatives: 3x OOD (phi/BAL/ADDR) + 2x SHAPE         %s\n", neg?"PASS":"FAIL");
        if(!neg)fails++;
    }

    free(flat);
    if(fails){ printf("test_conf_action_verify: FAIL (%d)\n",fails); free(fx); return 1; }
    printf("test_conf_action_verify: PASS\n");
    free(fx);
    (void)fp2eq;
    return 0;
}
