/**
 * @file test_fri_verify_zk.c
 * @brief M2b — end-to-end is_zk=1 FRI verification (HidingFriPcs), 82cfad73.
 *
 * Parses tools/vectors/stark_priming_zk.json (REAL is_zk=1 p3_uni_stark::prove
 * over HidingFriPcs), then on the DNAC C stack:
 *   1. build dnac_fri_proof_t from proof_serde[1] (the inner FriProof; the
 *      HidingFriPcs proof is the tuple [rand_cw_openings, inner_FriProof],
 *      hiding_pcs.rs). The rand codewords are ALREADY merged into the vector's
 *      opened_values (base ++ rand, hiding_pcs.rs::verify point.1.extend), so
 *      proof_serde[0] is skipped here.
 *   2. dnac_stark_prime_transcript with is_zk=1  (random-commit observe +
 *      random opened round FIRST, verifier.rs:383-411)
 *   3. build coms = [random, trace, quotient] (3 rounds; verifier.rs:403-458),
 *      quotient round = num_qc matrices, all claimed_evals MERGED (width 6).
 *   4. dnac_fri_verify  ->  MUST return DNAC_FRI_OK.
 *
 * This is the GROUND-TRUTH gate: if the is_zk transcript order, the merge, or
 * the 3-round coms assembly is wrong, dnac_fri_verify rejects. It validates the
 * M2a priming against the REAL verifier (not just the oracle's own Shadow).
 *
 * JSON scanner + serde parsers adapted from tools/gen_stark_proof_wire.c, with:
 *   - proof_serde parsed as a TUPLE array (skip [0], parse [1]);
 *   - multi-matrix input batches (the quotient batch carries num_qc matrices);
 *   - a random round prepended to the coms.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "field_goldilocks.h"
#include "fri_proof_codec.h"
#include "fri_verifier.h"
#include "stark_priming.h"
#include "transcript.h"

/* ===== JSON scanner (adapted from gen_stark_proof_wire.c) ===== */
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
static void put_u64_le(uint8_t *p,uint64_t v){ for(int i=0;i<8;i++)p[i]=(uint8_t)(v>>(8*i)); }
static int read_u64_array(js_t *s,uint64_t *out,int cap){ int n=0; js_match(s,'['); while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;} uint64_t v; if(!js_read_u64(s,&v))return -1; if(n<cap)out[n]=v; n++; } return n; }
static void parse_lanes_digest(js_t *s,uint8_t out[64]){ uint64_t l[8]={0}; read_u64_array(s,l,8); for(int i=0;i<8;i++)put_u64_le(out+i*8,l[i]); }
static void parse_commit_digest(js_t *s,uint8_t out[64]){
    js_match(s,'{'); while(!js_match(s,'}')){ if(js_peek(s,',')){s->pos++;continue;} char*k=js_read_string(s); js_match(s,':');
        if(k&&strcmp(k,"cap")==0){ js_match(s,'['); parse_lanes_digest(s,out); while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;} js_skip_value(s);} } else { js_skip_value(s); } free(k); }
}
static uint64_t parse_base_obj(js_t *s){ uint64_t r=0; js_match(s,'{'); while(!js_match(s,'}')){ if(js_peek(s,',')){s->pos++;continue;} char*k=js_read_string(s); js_match(s,':'); if(k&&strcmp(k,"value")==0)js_read_u64(s,&r); else js_skip_value(s); free(k);} return r; }
static gold_fp2_t parse_fp2_wrapped(js_t *s){
    uint64_t comps[2]={0,0}; int n=0; js_match(s,'{');
    while(!js_match(s,'}')){ if(js_peek(s,',')){s->pos++;continue;} char*k=js_read_string(s); js_match(s,':');
        if(k&&strcmp(k,"value")==0){ js_match(s,'['); while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;} uint64_t bv=parse_base_obj(s); if(n<2)comps[n]=bv; n++; } } else { js_skip_value(s); } free(k); }
    return gold_fp2_new(gold_fp_from_u64(comps[0]),gold_fp_from_u64(comps[1]));
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

/* ===== storage (is_zk: 3 rounds; quotient batch multi-matrix) ===== */
#define GXQ 8       /* queries              */
#define GXB 4       /* input batches/round: random,trace,quotient = 3 */
#define GXMAT 8     /* matrices per batch (quotient = num_qc)          */
#define GXR 16      /* commit-phase rounds  */
#define GXCOL 128   /* columns / evals (RangeProofAir trace width 56+4 rand = 60) */
#define GXSIB 16    /* siblings             */
#define GXCHUNK 8   /* quotient chunks      */

typedef struct {
    dnac_fri_params_t params;
    /* inner FriProof (proof_serde[1]) */
    dnac_merkle_digest_t commits[GXR]; size_t num_commits;
    gold_fp_t  witnesses[GXR];
    gold_fp2_t final_poly[GXCOL]; size_t num_final_poly;
    gold_fp_t  qpow;
    /* per query, per batch, per matrix committed row (base field) */
    gold_fp_t            inp_row[GXQ][GXB][GXMAT][GXCOL];
    const gold_fp_t     *inp_rowptr[GXQ][GXB][GXMAT];
    size_t               inp_lens[GXQ][GXB][GXMAT];
    size_t               inp_nmat[GXQ][GXB];
    dnac_merkle_digest_t inp_sib[GXQ][GXB][GXSIB];
    dnac_fri_batch_opening_t bo[GXQ][GXB]; size_t num_batches[GXQ];
    gold_fp2_t           cpo_sib[GXQ][GXR][GXSIB];
    dnac_merkle_digest_t cpo_psib[GXQ][GXR][GXSIB];
    dnac_fri_commit_phase_proof_step_t cpo[GXQ][GXR]; size_t cpo_n[GXQ];
    dnac_fri_query_proof_t qp[GXQ]; size_t num_queries;
    dnac_fri_proof_t proof;

    /* stark scalars + commitments */
    size_t degree_bits, num_quotient_chunks;
    dnac_merkle_digest_t trace_commit, quotient_commit, random_commit;
    gold_fp_t public_values[GXCOL]; size_t num_public_values;
    gold_fp2_t alpha_exp, zeta_exp, zeta_next_exp;
    /* MERGED opened values (base ++ rand) */
    gold_fp2_t random_local[GXCOL];  size_t random_local_len;
    gold_fp2_t trace_local[GXCOL];   size_t trace_local_len;
    gold_fp2_t trace_next[GXCOL];    size_t trace_next_len; int has_trace_next;
    gold_fp2_t quot_chunk[GXCHUNK][GXCOL]; size_t quot_chunk_len[GXCHUNK]; size_t num_quot_chunks_parsed;
    uint8_t init_state[256]; size_t init_state_len;

    /* built coms: 3 rounds (random, trace, quotient) */
    dnac_fri_opening_point_t rand_points[1];
    dnac_fri_opening_point_t trace_points[2];
    dnac_fri_opening_point_t quot_points[GXCHUNK];
    dnac_fri_matrix_openings_t rand_matrix;
    dnac_fri_matrix_openings_t trace_matrix;
    dnac_fri_matrix_openings_t quot_matrix[GXCHUNK];
    dnac_fri_commitment_with_opening_points_t cwop[3];
} gx_t;

static void parse_cpo(js_t *s,gx_t *fx,size_t q,size_t r){
    size_t nsib=0,npsib=0; uint8_t la=0; js_match(s,'{');
    while(!js_match(s,'}')){ if(js_peek(s,',')){s->pos++;continue;} char*k=js_read_string(s); js_match(s,':');
        if(k&&strcmp(k,"log_arity")==0){ uint64_t v; js_read_u64(s,&v); la=(uint8_t)v; }
        else if(k&&strcmp(k,"sibling_values")==0){ js_match(s,'['); while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;} gold_fp2_t fv=parse_fp2_wrapped(s); if(nsib<GXSIB)fx->cpo_sib[q][r][nsib]=fv; nsib++; } }
        else if(k&&strcmp(k,"opening_proof")==0){ js_match(s,'['); while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;} if(npsib<GXSIB)parse_lanes_digest(s,fx->cpo_psib[q][r][npsib].bytes); else js_skip_value(s); npsib++; } }
        else { js_skip_value(s); }
        free(k);
    }
    fx->cpo[q][r].log_arity=la; fx->cpo[q][r].sibling_values=fx->cpo_sib[q][r]; fx->cpo[q][r].num_sibling_values=nsib;
    fx->cpo[q][r].opening_proof.leaf_index=0; fx->cpo[q][r].opening_proof.depth=(uint32_t)npsib; fx->cpo[q][r].opening_proof.num_matrices=1; fx->cpo[q][r].opening_proof.siblings=fx->cpo_psib[q][r];
}
/* opened_values = [[matrix0 row],[matrix1 row],...] (Vec<Vec<Val>>, base field);
 * opening_proof = one Merkle path for the whole batch (same-height matrices). */
static void parse_input_batch(js_t *s,gx_t *fx,size_t q,size_t b){
    size_t nsib=0,nmat=0; js_match(s,'{');
    while(!js_match(s,'}')){ if(js_peek(s,',')){s->pos++;continue;} char*bk=js_read_string(s); js_match(s,':');
        if(bk&&strcmp(bk,"opened_values")==0){
            js_match(s,'[');                              /* outer: per-matrix */
            while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;}
                size_t ncols=0; js_match(s,'[');          /* inner: this matrix row */
                while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;} uint64_t bv=parse_base_obj(s); if(nmat<GXMAT&&ncols<GXCOL)fx->inp_row[q][b][nmat][ncols]=gold_fp_from_u64(bv); ncols++; }
                if(nmat<GXMAT){ fx->inp_lens[q][b][nmat]=ncols; fx->inp_rowptr[q][b][nmat]=fx->inp_row[q][b][nmat]; }
                nmat++;
            }
        }
        else if(bk&&strcmp(bk,"opening_proof")==0){ js_match(s,'['); while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;} if(nsib<GXSIB)parse_lanes_digest(s,fx->inp_sib[q][b][nsib].bytes); else js_skip_value(s); nsib++; } }
        else { js_skip_value(s); }
        free(bk);
    }
    fx->inp_nmat[q][b]=nmat;
    fx->bo[q][b].opened_values=fx->inp_rowptr[q][b]; fx->bo[q][b].opened_values_lens=fx->inp_lens[q][b]; fx->bo[q][b].num_matrices=nmat;
    fx->bo[q][b].opening_proof.leaf_index=0; fx->bo[q][b].opening_proof.depth=(uint32_t)nsib; fx->bo[q][b].opening_proof.num_matrices=nmat; fx->bo[q][b].opening_proof.siblings=fx->inp_sib[q][b];
}
static void parse_query_proof(js_t *s,gx_t *fx,size_t q){
    size_t ncpo=0,nbatch=0; js_match(s,'{');
    while(!js_match(s,'}')){ if(js_peek(s,',')){s->pos++;continue;} char*k=js_read_string(s); js_match(s,':');
        if(k&&strcmp(k,"input_proof")==0){ js_match(s,'['); while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;} if(nbatch<GXB){parse_input_batch(s,fx,q,nbatch);nbatch++;} else js_skip_value(s);} }
        else if(k&&strcmp(k,"commit_phase_openings")==0){ js_match(s,'['); while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;} if(ncpo<GXR){parse_cpo(s,fx,q,ncpo);ncpo++;} else js_skip_value(s);} }
        else { js_skip_value(s); }
        free(k);
    }
    fx->num_batches[q]=nbatch; fx->cpo_n[q]=ncpo;
    fx->qp[q].input_proof=fx->bo[q]; fx->qp[q].num_input_batches=nbatch; fx->qp[q].commit_phase_openings=fx->cpo[q]; fx->qp[q].num_commit_phase_openings=ncpo;
}
static void parse_inner_fri_proof(js_t *s,gx_t *fx){
    js_match(s,'{'); while(!js_match(s,'}')){ if(js_peek(s,',')){s->pos++;continue;} char*k=js_read_string(s); js_match(s,':');
        if(k&&strcmp(k,"commit_phase_commits")==0){ size_t n=0; js_match(s,'['); while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;} if(n<GXR)parse_commit_digest(s,fx->commits[n].bytes); else js_skip_value(s); n++; } fx->num_commits=n; }
        else if(k&&strcmp(k,"commit_pow_witnesses")==0){ size_t n=0; js_match(s,'['); while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;} uint64_t bv=parse_base_obj(s); if(n<GXR)fx->witnesses[n]=gold_fp_from_u64(bv); n++; } }
        else if(k&&strcmp(k,"final_poly")==0){ size_t n=0; js_match(s,'['); while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;} gold_fp2_t fv=parse_fp2_wrapped(s); if(n<GXCOL)fx->final_poly[n]=fv; n++; } fx->num_final_poly=n; }
        else if(k&&strcmp(k,"query_pow_witness")==0){ fx->qpow=gold_fp_from_u64(parse_base_obj(s)); }
        else if(k&&strcmp(k,"query_proofs")==0){ size_t n=0; js_match(s,'['); while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;} if(n<GXQ)parse_query_proof(s,fx,n); else js_skip_value(s); n++; } fx->num_queries=n; }
        else { js_skip_value(s); }
        free(k);
    }
}
/* proof_serde is the HidingFriPcs tuple array [rand_cw_openings, inner_FriProof].
 * rand codewords are already merged into opened_values -> skip [0], parse [1]. */
static void parse_proof_serde_tuple(js_t *s,gx_t *fx){
    js_match(s,'['); js_skip_value(s); /* [0] rand_cw_openings (already merged) */
    if(js_peek(s,',')) s->pos++;
    parse_inner_fri_proof(s,fx);        /* [1] inner FriProof */
    while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;} js_skip_value(s);}
}
static void parse_params(js_t *s,gx_t *fx){
    js_match(s,'{'); while(!js_match(s,'}')){ if(js_peek(s,',')){s->pos++;continue;} char*k=js_read_string(s); js_match(s,':'); uint64_t v=0; js_read_u64(s,&v);
        if(k&&strcmp(k,"log_blowup")==0)fx->params.log_blowup=v; else if(k&&strcmp(k,"log_final_poly_len")==0)fx->params.log_final_poly_len=v; else if(k&&strcmp(k,"max_log_arity")==0)fx->params.max_log_arity=v; else if(k&&strcmp(k,"num_queries")==0)fx->params.num_queries=v; else if(k&&strcmp(k,"commit_proof_of_work_bits")==0)fx->params.commit_proof_of_work_bits=v; else if(k&&strcmp(k,"query_proof_of_work_bits")==0)fx->params.query_proof_of_work_bits=v; free(k); }
}
static void parse_instance(js_t *s,gx_t *fx){
    js_match(s,'{'); while(!js_match(s,'}')){ if(js_peek(s,',')){s->pos++;continue;} char*k=js_read_string(s); js_match(s,':'); uint64_t v=0; js_read_u64(s,&v);
        if(k&&strcmp(k,"degree_bits")==0)fx->degree_bits=(size_t)v; else if(k&&strcmp(k,"num_quotient_chunks")==0)fx->num_quotient_chunks=(size_t)v; free(k); }
}
static void parse_commitments(js_t *s,gx_t *fx){
    js_match(s,'{'); while(!js_match(s,'}')){ if(js_peek(s,',')){s->pos++;continue;} char*k=js_read_string(s); js_match(s,':');
        if(k&&strcmp(k,"trace_commit_root_hex")==0){ char*h=js_read_string(s); hex_decode(h,fx->trace_commit.bytes,DNAC_MERKLE_DIGEST_BYTES); free(h); }
        else if(k&&strcmp(k,"quotient_commit_root_hex")==0){ char*h=js_read_string(s); hex_decode(h,fx->quotient_commit.bytes,DNAC_MERKLE_DIGEST_BYTES); free(h); }
        else if(k&&strcmp(k,"random_commit_root_hex")==0){ char*h=js_read_string(s); hex_decode(h,fx->random_commit.bytes,DNAC_MERKLE_DIGEST_BYTES); free(h); }
        else { js_skip_value(s); } free(k); }
}
static void parse_public_values(js_t *s,gx_t *fx){
    size_t n=0; js_match(s,'['); while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;} char*v=js_read_string(s); if(v&&n<GXCOL)fx->public_values[n]=gold_fp_from_u64(strtoull(v,NULL,10)); free(v); n++; } fx->num_public_values=n;
}
static void parse_challenges(js_t *s,gx_t *fx){
    js_match(s,'{'); while(!js_match(s,'}')){ if(js_peek(s,',')){s->pos++;continue;} char*k=js_read_string(s); js_match(s,':');
        if(k&&strcmp(k,"stark_alpha_fp2")==0)fx->alpha_exp=parse_fp2_decimal(s); else if(k&&strcmp(k,"zeta_fp2")==0)fx->zeta_exp=parse_fp2_decimal(s); else if(k&&strcmp(k,"zeta_next_fp2")==0)fx->zeta_next_exp=parse_fp2_decimal(s); else { js_skip_value(s); } free(k); }
}
static void parse_opened(js_t *s,gx_t *fx){
    js_match(s,'{'); while(!js_match(s,'}')){ if(js_peek(s,',')){s->pos++;continue;} char*k=js_read_string(s); js_match(s,':');
        if(k&&strcmp(k,"random")==0)fx->random_local_len=parse_fp2_decimal_array(s,fx->random_local,GXCOL);
        else if(k&&strcmp(k,"trace_local")==0)fx->trace_local_len=parse_fp2_decimal_array(s,fx->trace_local,GXCOL);
        else if(k&&strcmp(k,"trace_next")==0){ if(js_peek(s,'[')){ fx->trace_next_len=parse_fp2_decimal_array(s,fx->trace_next,GXCOL); fx->has_trace_next=1; } else { js_skip_value(s); fx->has_trace_next=0; } }
        else if(k&&strcmp(k,"quotient_chunks")==0){ size_t c=0; js_match(s,'['); while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;} if(c<GXCHUNK)fx->quot_chunk_len[c]=parse_fp2_decimal_array(s,fx->quot_chunk[c],GXCOL); else js_skip_value(s); c++; } fx->num_quot_chunks_parsed=c; }
        else { js_skip_value(s); } free(k); }
}

static void wire_proof(gx_t *fx){
    fx->proof.commit_phase_commits=fx->commits; fx->proof.num_commit_phase_commits=fx->num_commits;
    fx->proof.commit_pow_witnesses=fx->witnesses; fx->proof.num_commit_pow_witnesses=fx->num_commits;
    fx->proof.query_proofs=fx->qp; fx->proof.num_query_proofs=fx->num_queries;
    fx->proof.final_poly=fx->final_poly; fx->proof.num_final_poly=fx->num_final_poly;
    fx->proof.query_pow_witness=fx->qpow;
}

/* coms = [random, trace, quotient] (verifier.rs:403-458). All matrices open at
 * the natural domain (log_size=degree_bits, shift=ONE derived by the verifier);
 * claimed_evals are the MERGED (base ++ rand) vectors. */
static void build_coms(gx_t *fx, gold_fp2_t zeta, gold_fp2_t zeta_next){
    /* round 0: random — 1 matrix, 1 point (zeta, random_local) */
    fx->rand_points[0].point=zeta; fx->rand_points[0].claimed_evals=fx->random_local; fx->rand_points[0].num_claimed_evals=fx->random_local_len;
    fx->rand_matrix.domain.shift=gold_fp_from_u64(0); fx->rand_matrix.domain.shift_inverse=gold_fp_from_u64(0); fx->rand_matrix.domain.log_size=fx->degree_bits;
    fx->rand_matrix.points=fx->rand_points; fx->rand_matrix.num_points=1;
    fx->cwop[0].commitment=fx->random_commit; fx->cwop[0].matrices=&fx->rand_matrix; fx->cwop[0].num_matrices=1;

    /* round 1: trace — 1 matrix, points (zeta,trace_local)[+(zeta_next,trace_next)] */
    fx->trace_points[0].point=zeta; fx->trace_points[0].claimed_evals=fx->trace_local; fx->trace_points[0].num_claimed_evals=fx->trace_local_len;
    size_t np=1;
    if(fx->has_trace_next){ fx->trace_points[1].point=zeta_next; fx->trace_points[1].claimed_evals=fx->trace_next; fx->trace_points[1].num_claimed_evals=fx->trace_next_len; np=2; }
    fx->trace_matrix.domain.shift=gold_fp_from_u64(0); fx->trace_matrix.domain.shift_inverse=gold_fp_from_u64(0); fx->trace_matrix.domain.log_size=fx->degree_bits;
    fx->trace_matrix.points=fx->trace_points; fx->trace_matrix.num_points=np;
    fx->cwop[1].commitment=fx->trace_commit; fx->cwop[1].matrices=&fx->trace_matrix; fx->cwop[1].num_matrices=1;

    /* round 2: quotient — num_qc matrices, each 1 point (zeta, chunk_c) */
    for(size_t c=0;c<fx->num_quot_chunks_parsed;c++){
        fx->quot_points[c].point=zeta; fx->quot_points[c].claimed_evals=fx->quot_chunk[c]; fx->quot_points[c].num_claimed_evals=fx->quot_chunk_len[c];
        fx->quot_matrix[c].domain.shift=gold_fp_from_u64(0); fx->quot_matrix[c].domain.shift_inverse=gold_fp_from_u64(0); fx->quot_matrix[c].domain.log_size=fx->degree_bits;
        fx->quot_matrix[c].points=&fx->quot_points[c]; fx->quot_matrix[c].num_points=1;
    }
    fx->cwop[2].commitment=fx->quotient_commit; fx->cwop[2].matrices=fx->quot_matrix; fx->cwop[2].num_matrices=fx->num_quot_chunks_parsed;
}

int main(int argc,char **argv){
    if(argc<2){ fprintf(stderr,"usage: %s <stark_priming_zk.json>\n",argv[0]); return 2; }
    gx_t *fx=(gx_t*)calloc(1,sizeof *fx); if(!fx)return 2;
    size_t bl=0; char *blob=slurp(argv[1],&bl); if(!blob){ fprintf(stderr,"cannot read %s\n",argv[1]); free(fx); return 2; }
    js_t s={blob,0,bl}; js_match(&s,'{');
    while(!js_match(&s,'}')){ if(js_peek(&s,',')){s.pos++;continue;} char*k=js_read_string(&s); if(!k)break; js_match(&s,':');
        if(k&&strcmp(k,"instance")==0)parse_instance(&s,fx);
        else if(k&&strcmp(k,"fri_params")==0)parse_params(&s,fx);
        else if(k&&strcmp(k,"proof_serde")==0)parse_proof_serde_tuple(&s,fx);
        else if(k&&strcmp(k,"commitments")==0)parse_commitments(&s,fx);
        else if(k&&strcmp(k,"public_values")==0)parse_public_values(&s,fx);
        else if(k&&strcmp(k,"challenges")==0)parse_challenges(&s,fx);
        else if(k&&strcmp(k,"opened_values")==0)parse_opened(&s,fx);
        else if(k&&strcmp(k,"init_state_hex")==0){ char*h=js_read_string(&s); fx->init_state_len=hex_decode(h,fx->init_state,sizeof fx->init_state); free(h); }
        else js_skip_value(&s);
        free(k);
    }
    free(blob);
    wire_proof(fx);

    /* ---- priming (is_zk=1) ---- */
    dnac_stark_priming_input_t in; memset(&in,0,sizeof in);
    in.degree_bits=fx->degree_bits; in.is_zk=1; in.preprocessed_width=0;
    in.trace_commit=fx->trace_commit; in.quotient_commit=fx->quotient_commit;
    in.random_commit=&fx->random_commit;
    in.random_local=fx->random_local; in.random_local_len=fx->random_local_len;
    in.public_values=fx->public_values; in.num_public_values=fx->num_public_values;
    in.trace_local=fx->trace_local; in.trace_local_len=fx->trace_local_len;
    in.trace_next=fx->has_trace_next?fx->trace_next:NULL; in.trace_next_len=fx->trace_next_len;
    const gold_fp2_t *qcptr[GXCHUNK]; size_t qclen[GXCHUNK];
    for(size_t c=0;c<fx->num_quot_chunks_parsed;c++){ qcptr[c]=fx->quot_chunk[c]; qclen[c]=fx->quot_chunk_len[c]; }
    in.quotient_chunks=qcptr; in.quotient_chunk_lens=qclen; in.num_quotient_chunks=fx->num_quot_chunks_parsed;

    dnac_transcript_t *t=dnac_transcript_init(fx->init_state,fx->init_state_len);
    if(!t){ fprintf(stderr,"transcript init failed\n"); free(fx); return 1; }
    dnac_stark_priming_out_t out; memset(&out,0,sizeof out);
    if(dnac_stark_prime_transcript(t,&in,&out)!=DNAC_STARK_PRIMING_OK){ fprintf(stderr,"priming failed\n"); return 1; }
    if(!gold_fp2_eq(out.alpha,fx->alpha_exp)||!gold_fp2_eq(out.zeta,fx->zeta_exp)||!gold_fp2_eq(out.zeta_next,fx->zeta_next_exp)){
        fprintf(stderr,"MISMATCH: priming alpha/zeta/zeta_next != vector challenges\n"); return 1;
    }

    /* ---- build 3-round coms + dnac_fri_verify (GROUND-TRUTH gate) ---- */
    build_coms(fx,out.zeta,out.zeta_next);
    dnac_fri_status_t fs=dnac_fri_verify(&fx->params,&fx->proof,t,fx->cwop,3);
    dnac_transcript_free(t);
    if(fs!=DNAC_FRI_OK){
        fprintf(stderr,"GATE FAILED: dnac_fri_verify(is_zk) -> %d (want 0=DNAC_FRI_OK)\n",(int)fs);
        fprintf(stderr,"  degree_bits=%zu num_qc=%zu queries=%zu batches[0]=%zu random_len=%zu\n",
                fx->degree_bits, fx->num_quot_chunks_parsed, fx->num_queries, fx->num_batches[0], fx->random_local_len);
        free(fx); return 1;
    }

    printf("test_fri_verify_zk: PASS\n");
    printf("  is_zk=1 end-to-end: dnac_stark_prime_transcript -> dnac_fri_verify = DNAC_FRI_OK.\n");
    printf("  coms = [random, trace, quotient x%zu]; merged opened widths: random=%zu trace=%zu quot=%zu.\n",
           fx->num_quot_chunks_parsed, fx->random_local_len, fx->trace_local_len, fx->quot_chunk_len[0]);
    printf("  This grounds the is_zk priming against the REAL Plonky3 HidingFriPcs verifier (82cfad73).\n");
    free(fx);
    return 0;
}
