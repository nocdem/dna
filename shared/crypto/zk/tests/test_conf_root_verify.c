/**
 * @file test_conf_root_verify.c
 * @brief B1 Stage-2 — C constraint-check layer vs the REAL Plonky3 verifier
 *        functions on the COMBINED confidential AIR (width 614, is_zk=1,
 *        num_qc=8), 82cfad73.
 *
 * Consumes tools/vectors/conf_root_air_zk{,_h16}.json. The vector's
 * "constraint_check" block is produced by the REAL pub Plonky3 functions
 * (recompose_quotient_from_chunks verifier.rs:59-96 over the UNrandomized
 * split domains verifier.rs:305-312,463-467; selectors_at_point
 * domain.rs:262-271 on init_trace_domain verifier.rs:303) — NOT a shadow.
 *
 * Gates:
 *   T1  shape: is_zk=1 fold consistency (num_qc == 1 << (log_num_qc + 1)).
 *   T2  C dnac_stark_selectors_at_point == REAL selectors (4 fp2).
 *   T3  C chunk-domain shifts (7 * g_Q^i) == REAL split_domains shifts;
 *       chunk log_size == degree_bits - is_zk.
 *   T4  C dnac_stark_recompose_quotient_nchunk (merged chunks, stride 6,
 *       first 2 read) == REAL quotient(zeta).
 *   T5  teeth + fail-close: tampered chunk -> different quotient; wrong
 *       log_num_qc / num_qc / stride -> ERR_SHAPE.
 *
 * (The combined-AIR air_eval + final OOD check land in the Faz-3 extension of
 * this test.)
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "conf_root_fold.h"
#include "field_goldilocks.h"
#include "stark_constraints.h"

/* ===== JSON scanner (test-local convention; adapted from test_fri_verify_zk.c) ===== */
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

/* ===== fixture ===== */
#define CV_W 640
#define CV_QC 8
#define CV_PUB 32

typedef struct {
    size_t degree_bits, num_quotient_chunks;
    gold_fp2_t alpha, zeta, zeta_next;
    /* constraint_check ground truth (REAL Plonky3 fn outputs) */
    size_t log_num_qc;
    uint64_t chunk_shift[CV_QC]; size_t chunk_log[CV_QC]; size_t num_chunk_domains;
    gold_fp2_t sel_first, sel_last, sel_trans, sel_invvan;
    gold_fp2_t quotient_zeta;
    /* merged opened values */
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
static void parse_chunk_domains(js_t *s,cv_t *fx){
    size_t n=0; js_match(s,'[');
    while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;}
        uint64_t shift=0,lsz=0; js_match(s,'{');
        while(!js_match(s,'}')){ if(js_peek(s,',')){s->pos++;continue;} char*k=js_read_string(s); js_match(s,':');
            if(k&&strcmp(k,"shift_decimal")==0){ char*v=js_read_string(s); if(v)shift=strtoull(v,NULL,10); free(v); }
            else if(k&&strcmp(k,"log_size")==0)js_read_u64(s,&lsz);
            else js_skip_value(s);
            free(k); }
        if(n<CV_QC){ fx->chunk_shift[n]=shift; fx->chunk_log[n]=(size_t)lsz; } n++;
    }
    fx->num_chunk_domains=n;
}
static void parse_constraint_check(js_t *s,cv_t *fx){
    js_match(s,'{'); while(!js_match(s,'}')){ if(js_peek(s,',')){s->pos++;continue;} char*k=js_read_string(s); js_match(s,':');
        if(k&&strcmp(k,"log_num_quotient_chunks")==0){ uint64_t v=0; js_read_u64(s,&v); fx->log_num_qc=(size_t)v; }
        else if(k&&strcmp(k,"chunk_domains")==0)parse_chunk_domains(s,fx);
        else if(k&&strcmp(k,"selectors_at_zeta")==0){
            js_match(s,'{'); while(!js_match(s,'}')){ if(js_peek(s,',')){s->pos++;continue;} char*sk=js_read_string(s); js_match(s,':');
                if(sk&&strcmp(sk,"is_first_row")==0)fx->sel_first=parse_fp2_decimal(s);
                else if(sk&&strcmp(sk,"is_last_row")==0)fx->sel_last=parse_fp2_decimal(s);
                else if(sk&&strcmp(sk,"is_transition")==0)fx->sel_trans=parse_fp2_decimal(s);
                else if(sk&&strcmp(sk,"inv_vanishing")==0)fx->sel_invvan=parse_fp2_decimal(s);
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
    if(argc<2){ fprintf(stderr,"usage: %s <conf_root_air_zk.json>\n",argv[0]); return 2; }
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
    int fails=0;

    /* T1 — shape consistency (verifier.rs:294-296). */
    {
        int ok = fx->num_quotient_chunks==CV_QC
              && fx->log_num_qc==2
              && fx->num_quotient_chunks==((size_t)1<<(fx->log_num_qc+is_zk))
              && fx->num_quot_chunks_parsed==fx->num_quotient_chunks
              && fx->num_chunk_domains==fx->num_quotient_chunks
              && fx->num_public_values==17;
        printf("  T1 shape: num_qc=8, log_num_qc=2, publics=17          %s\n", ok?"PASS":"FAIL");
        if(!ok)fails++;
    }

    /* T2 — C selectors == REAL selectors_at_point (init_trace_domain,
     * base_degree_bits = degree_bits - is_zk; verifier.rs:303,488). */
    {
        dnac_stark_selectors_t cs =
            dnac_stark_selectors_at_point(fx->zeta, fx->degree_bits - is_zk);
        int ok = fp2eq(cs.is_first_row,fx->sel_first)
              && fp2eq(cs.is_last_row,fx->sel_last)
              && fp2eq(cs.is_transition,fx->sel_trans)
              && fp2eq(cs.inv_vanishing,fx->sel_invvan);
        printf("  T2 selectors byte-match REAL selectors_at_point       %s\n", ok?"PASS":"FAIL");
        if(!ok)fails++;
    }

    /* T3 — C chunk-domain shifts (7 * g_Q^i) == REAL split_domains shifts. */
    {
        const size_t q_log = fx->degree_bits + fx->log_num_qc;
        const gold_fp_t g_q = gold_fp_two_adic_generator((unsigned)q_log);
        gold_fp_t sft = gold_fp_from_u64(GOLDILOCKS_GENERATOR);
        int ok = 1;
        for(size_t i=0;i<fx->num_chunk_domains;i++){
            if(!gold_fp_eq(sft,gold_fp_from_u64(fx->chunk_shift[i]))) ok=0;
            if(fx->chunk_log[i]!=fx->degree_bits-is_zk) ok=0;
            sft = gold_fp_mul(sft,g_q);
        }
        printf("  T3 chunk-domain shifts 7*g_Q^i == REAL split_domains  %s\n", ok?"PASS":"FAIL");
        if(!ok)fails++;
    }

    /* T4 — THE gate: C N-chunk recompose == REAL recompose_quotient_from_chunks.
     * Chunks are the MERGED vectors (width 6); the recompose reads the first 2
     * (hiding_pcs.rs:349 split boundary). */
    {
        gold_fp2_t flat[CV_QC*8]; size_t stride=fx->quot_chunk_len[0];
        for(size_t c=0;c<CV_QC;c++)
            for(size_t j=0;j<stride&&j<8;j++)
                flat[c*stride+j]=fx->quot_chunk[c][j];
        gold_fp2_t q;
        dnac_stark_verify_status_t st = dnac_stark_recompose_quotient_nchunk(
            fx->zeta, fx->degree_bits, fx->log_num_qc, is_zk,
            flat, CV_QC, stride, &q);
        int ok = (st==DNAC_STARK_VERIFY_OK) && fp2eq(q,fx->quotient_zeta);
        printf("  T4 C nchunk recompose == REAL quotient(zeta)          %s\n", ok?"PASS":"FAIL");
        if(!ok){ fails++; }

        /* T5 — teeth + fail-close. */
        int teeth = 1;
        /* (a) tampered chunk value -> different quotient */
        flat[3*stride+1] = gold_fp2_add(flat[3*stride+1], gold_fp2_one());
        gold_fp2_t q2;
        if(dnac_stark_recompose_quotient_nchunk(fx->zeta,fx->degree_bits,fx->log_num_qc,is_zk,flat,CV_QC,stride,&q2)!=DNAC_STARK_VERIFY_OK) teeth=0;
        if(fp2eq(q2,fx->quotient_zeta)) teeth=0;
        flat[3*stride+1] = gold_fp2_sub(flat[3*stride+1], gold_fp2_one());
        /* (b) wrong log_num_qc -> num_qc mismatch -> SHAPE */
        if(dnac_stark_recompose_quotient_nchunk(fx->zeta,fx->degree_bits,1,is_zk,flat,CV_QC,stride,&q2)!=DNAC_STARK_VERIFY_ERR_SHAPE) teeth=0;
        /* (c) num_qc mismatch -> SHAPE */
        if(dnac_stark_recompose_quotient_nchunk(fx->zeta,fx->degree_bits,fx->log_num_qc,is_zk,flat,4,stride,&q2)!=DNAC_STARK_VERIFY_ERR_SHAPE) teeth=0;
        /* (d) stride < 2 -> SHAPE */
        if(dnac_stark_recompose_quotient_nchunk(fx->zeta,fx->degree_bits,fx->log_num_qc,is_zk,flat,CV_QC,1,&q2)!=DNAC_STARK_VERIFY_ERR_SHAPE) teeth=0;
        /* (e) NULL out -> SHAPE */
        if(dnac_stark_recompose_quotient_nchunk(fx->zeta,fx->degree_bits,fx->log_num_qc,is_zk,flat,CV_QC,stride,NULL)!=DNAC_STARK_VERIFY_ERR_SHAPE) teeth=0;
        printf("  T5 teeth: tamper differs + 4/4 fail-close SHAPE       %s\n", teeth?"PASS":"FAIL");
        if(!teeth)fails++;
    }

    /* T6 — THE Faz-3 gate: the C combined air_eval (fold form), driven by the
     * REAL proof's opened values, must satisfy folded * inv_vanishing ==
     * quotient(zeta). This pins constraint CONTENT and EMISSION ORDER against
     * a REAL Plonky3 is_zk=1 proof. Trace vectors are the merged (base ++ 4
     * random) opened values; the constraint layer consumes the UNMERGED first
     * 614 (hiding_pcs.rs:349 split boundary = len - 4). */
    {
        const size_t W = CONF_ROOT_WIDTH;
        int ok = fx->trace_local_len==W+4 && fx->trace_next_len==W+4;
        gold_fp2_t flat[CV_QC*8]; size_t stride=fx->quot_chunk_len[0];
        for(size_t cc=0;cc<CV_QC;cc++)
            for(size_t j=0;j<stride&&j<8;j++)
                flat[cc*stride+j]=fx->quot_chunk[cc][j];
        dnac_stark_verify_status_t st = dnac_stark_verify_constraints_nchunk(
            &DNAC_CONF_ROOT_FOLD_AIR,
            fx->trace_local, W, fx->trace_next, W,
            fx->public_values, fx->num_public_values,
            fx->zeta, fx->degree_bits, fx->log_num_qc, is_zk,
            fx->alpha, flat, CV_QC, stride);
        ok = ok && (st==DNAC_STARK_VERIFY_OK);
        printf("  T6 combined air_eval fold: verify_constraints==OK      %s\n", ok?"PASS":"FAIL");
        if(!ok){ printf("     (status=%d local_len=%zu next_len=%zu)\n",(int)st,fx->trace_local_len,fx->trace_next_len); fails++; }

        /* T7 — negatives through the FULL constraint check. */
        int neg = 1;
        #define RUN_NCHUNK() dnac_stark_verify_constraints_nchunk( \
            &DNAC_CONF_ROOT_FOLD_AIR, fx->trace_local, W, fx->trace_next, W, \
            fx->public_values, fx->num_public_values, fx->zeta, fx->degree_bits, \
            fx->log_num_qc, is_zk, fx->alpha, flat, CV_QC, stride)
        /* (a) tampered amount cell -> OOD */
        fx->trace_local[0]=gold_fp2_add(fx->trace_local[0],gold_fp2_one());
        if(RUN_NCHUNK()!=DNAC_STARK_VERIFY_ERR_OOD_MISMATCH)neg=0;
        fx->trace_local[0]=gold_fp2_sub(fx->trace_local[0],gold_fp2_one());
        /* (b) tampered commitment_root public -> OOD (R23-R26 binding) */
        fx->public_values[0]=gold_fp_add(fx->public_values[0],gold_fp_one());
        if(RUN_NCHUNK()!=DNAC_STARK_VERIFY_ERR_OOD_MISMATCH)neg=0;
        fx->public_values[0]=gold_fp_sub(fx->public_values[0],gold_fp_one());
        /* (c) tampered c_claimed public -> OOD (PB1-PB4 binding teeth) */
        fx->public_values[4]=gold_fp_add(fx->public_values[4],gold_fp_one());
        if(RUN_NCHUNK()!=DNAC_STARK_VERIFY_ERR_OOD_MISMATCH)neg=0;
        fx->public_values[4]=gold_fp_sub(fx->public_values[4],gold_fp_one());
        /* (d) tampered c_fee public -> OOD (PB5-PB8) */
        fx->public_values[8]=gold_fp_add(fx->public_values[8],gold_fp_one());
        if(RUN_NCHUNK()!=DNAC_STARK_VERIFY_ERR_OOD_MISMATCH)neg=0;
        fx->public_values[8]=gold_fp_sub(fx->public_values[8],gold_fp_one());
        /* (e) tampered hash_id public -> OOD (V4' reads publics[12]) */
        fx->public_values[12]=gold_fp_add(fx->public_values[12],gold_fp_one());
        if(RUN_NCHUNK()!=DNAC_STARK_VERIFY_ERR_OOD_MISMATCH)neg=0;
        fx->public_values[12]=gold_fp_sub(fx->public_values[12],gold_fp_one());
        /* (f) tampered tx_binding public -> constraint check stays OK
         * (HONEST BOUNDARY: the eval never reads publics[13..17); tx_binding
         * binds via the Fiat-Shamir transcript — a tampered tx_binding changes
         * alpha/zeta and every FRI challenge, caught by the priming +
         * dnac_fri_verify layer, NOT here). */
        fx->public_values[13]=gold_fp_add(fx->public_values[13],gold_fp_one());
        if(RUN_NCHUNK()!=DNAC_STARK_VERIFY_OK)neg=0;
        fx->public_values[13]=gold_fp_sub(fx->public_values[13],gold_fp_one());
        /* (g) wrong publics count -> SHAPE */
        if(dnac_stark_verify_constraints_nchunk(&DNAC_CONF_ROOT_FOLD_AIR,
            fx->trace_local,W,fx->trace_next,W,fx->public_values,16,
            fx->zeta,fx->degree_bits,fx->log_num_qc,is_zk,fx->alpha,flat,CV_QC,stride)
            !=DNAC_STARK_VERIFY_ERR_SHAPE)neg=0;
        /* (h) missing trace_next (main_next=1) -> SHAPE */
        if(dnac_stark_verify_constraints_nchunk(&DNAC_CONF_ROOT_FOLD_AIR,
            fx->trace_local,W,NULL,0,fx->public_values,fx->num_public_values,
            fx->zeta,fx->degree_bits,fx->log_num_qc,is_zk,fx->alpha,flat,CV_QC,stride)
            !=DNAC_STARK_VERIFY_ERR_SHAPE)neg=0;
        #undef RUN_NCHUNK
        printf("  T7 negatives: 5x OOD + tx_binding-FS-boundary + 2x SHAPE %s\n", neg?"PASS":"FAIL");
        if(!neg)fails++;
    }

    if(fails){ printf("test_conf_root_verify: FAIL (%d)\n",fails); free(fx); return 1; }
    printf("test_conf_root_verify: PASS\n");
    printf("  C selectors + chunk shifts + N-chunk recompose byte-match the REAL\n");
    printf("  Plonky3 verifier fns; combined air_eval (fold form) satisfies the OOD\n");
    printf("  equation on a REAL is_zk=1 proof (82cfad73, width 614, num_qc=8).\n");
    free(fx);
    return 0;
}
