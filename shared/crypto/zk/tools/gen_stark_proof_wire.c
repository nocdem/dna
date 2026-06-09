/**
 * @file gen_stark_proof_wire.c
 * @brief Build-time generator for tools/vectors/stark_proof_wire.json (P6).
 *
 * Builds the REAL FibonacciAir DZKS wrapper around the FibonacciAir FRI proof
 * (its DZKF inner), bound to the FibonacciAir STARK scalars — replacing the P5
 * placeholder V6 inner. Pipeline (all C, single wire source):
 *   parse stark_priming.json (proof_serde [Plonky3 FriProof] + commitments +
 *     opened_values + fri_params + challenges + public_values + instance)
 *   -> build dnac_fri_proof_t + CommitmentWithOpeningPoints
 *      (trace: 2 points (zeta,trace_local)+(zeta_next,trace_next) since
 *       FibonacciAir main_next=true; quotient: num_qc points (zeta,chunk_i);
 *       no preprocessed; no random ZK commitment)
 *   -> dnac_stark_prime_transcript (priming layer, P3) -> alpha/zeta/zeta_next
 *   -> dnac_fri_proof_encode (DZKF) -> dnac_fri_proof_decode -> dnac_fri_verify
 *      (GATE: must return DNAC_FRI_OK; if not, abort + report — no wire written)
 *   -> dnac_stark_proof_encode (DZKS wrapper) + 8 malformed negatives -> JSON.
 *
 * proof_serde parser copied verbatim from tools/gen_fri_proof_wire.c (the same
 * Plonky3 FriProof serde shape). Deterministic; regenerate-and-compare.
 *
 * Usage: gen_stark_proof_wire <stark_priming.json> <out stark_proof_wire.json>
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
#include "stark_proof_codec.h"
#include "transcript.h"

/* ===== JSON scanner + serde parsers (copied verbatim from gen_fri_proof_wire.c) ===== */
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
static void fput_hex(FILE *f,const uint8_t *b,size_t n){ static const char *H="0123456789abcdef"; for(size_t i=0;i<n;i++){ fputc(H[b[i]>>4],f); fputc(H[b[i]&0xF],f);} }
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

/* ===== storage (multi-commitment / multi-batch; FibonacciAir = 2 commitments) ===== */
#define GXQ 4
#define GXB 4
#define GXR 12
#define GXCOL 16
#define GXSIB 16
#define GXCHUNK 8

typedef struct {
    dnac_fri_params_t params;
    /* proof_serde */
    dnac_merkle_digest_t commits[GXR]; size_t num_commits;
    gold_fp_t  witnesses[GXR];
    gold_fp2_t final_poly[GXCOL]; size_t num_final_poly;
    gold_fp_t  qpow;
    gold_fp_t            inp_row[GXQ][GXB][GXCOL];
    const gold_fp_t     *inp_rowptr[GXQ][GXB][1];
    size_t               inp_lens[GXQ][GXB][1];
    dnac_merkle_digest_t inp_sib[GXQ][GXB][GXSIB]; size_t inp_depth[GXQ][GXB];
    dnac_fri_batch_opening_t bo[GXQ][GXB]; size_t num_batches[GXQ];
    gold_fp2_t           cpo_sib[GXQ][GXR][GXSIB]; size_t cpo_nsib[GXQ][GXR];
    dnac_merkle_digest_t cpo_psib[GXQ][GXR][GXSIB]; size_t cpo_pdepth[GXQ][GXR];
    dnac_fri_commit_phase_proof_step_t cpo[GXQ][GXR]; size_t cpo_n[GXQ];
    dnac_fri_query_proof_t qp[GXQ]; size_t num_queries;
    dnac_fri_proof_t proof;

    /* stark_priming-specific */
    size_t degree_bits, num_quotient_chunks;
    dnac_merkle_digest_t trace_commit, quotient_commit;
    gold_fp_t public_values[GXCOL]; size_t num_public_values;
    gold_fp2_t alpha_exp, zeta_exp, zeta_next_exp;
    gold_fp2_t trace_local[GXCOL]; size_t trace_local_len;
    gold_fp2_t trace_next[GXCOL];  size_t trace_next_len; int has_trace_next;
    gold_fp2_t quot_chunk[GXCHUNK][GXCOL]; size_t quot_chunk_len[GXCHUNK]; size_t num_quot_chunks_parsed;
    uint8_t input_buf_exp[1024]; size_t input_buf_exp_len;
    uint8_t init_state[256]; size_t init_state_len;

    /* built coms */
    dnac_fri_opening_point_t trace_points[2];
    dnac_fri_opening_point_t quot_points[GXCHUNK];
    dnac_fri_matrix_openings_t trace_matrix;
    dnac_fri_matrix_openings_t quot_matrix[GXCHUNK];
    dnac_fri_commitment_with_opening_points_t cwop[2];
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
    fx->cpo_nsib[q][r]=nsib; fx->cpo_pdepth[q][r]=npsib;
    fx->cpo[q][r].log_arity=la; fx->cpo[q][r].sibling_values=fx->cpo_sib[q][r]; fx->cpo[q][r].num_sibling_values=nsib;
    fx->cpo[q][r].opening_proof.leaf_index=0; fx->cpo[q][r].opening_proof.depth=(uint32_t)npsib; fx->cpo[q][r].opening_proof.num_matrices=1; fx->cpo[q][r].opening_proof.siblings=fx->cpo_psib[q][r];
}
static void parse_input_batch(js_t *s,gx_t *fx,size_t q,size_t b){
    size_t ncols=0,nsib=0; js_match(s,'{');
    while(!js_match(s,'}')){ if(js_peek(s,',')){s->pos++;continue;} char*bk=js_read_string(s); js_match(s,':');
        if(bk&&strcmp(bk,"opened_values")==0){ js_match(s,'['); js_match(s,'['); while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;} uint64_t bv=parse_base_obj(s); if(ncols<GXCOL)fx->inp_row[q][b][ncols]=gold_fp_from_u64(bv); ncols++; } while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;} js_skip_value(s);} }
        else if(bk&&strcmp(bk,"opening_proof")==0){ js_match(s,'['); while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;} if(nsib<GXSIB)parse_lanes_digest(s,fx->inp_sib[q][b][nsib].bytes); else js_skip_value(s); nsib++; } }
        else { js_skip_value(s); }
        free(bk);
    }
    fx->inp_lens[q][b][0]=ncols; fx->inp_depth[q][b]=nsib; fx->inp_rowptr[q][b][0]=fx->inp_row[q][b];
    fx->bo[q][b].opened_values=fx->inp_rowptr[q][b]; fx->bo[q][b].opened_values_lens=fx->inp_lens[q][b]; fx->bo[q][b].num_matrices=1;
    fx->bo[q][b].opening_proof.leaf_index=0; fx->bo[q][b].opening_proof.depth=(uint32_t)nsib; fx->bo[q][b].opening_proof.num_matrices=1; fx->bo[q][b].opening_proof.siblings=fx->inp_sib[q][b];
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
static void parse_params(js_t *s,gx_t *fx){
    js_match(s,'{'); while(!js_match(s,'}')){ if(js_peek(s,',')){s->pos++;continue;} char*k=js_read_string(s); js_match(s,':'); uint64_t v=0; js_read_u64(s,&v);
        if(k&&strcmp(k,"log_blowup")==0)fx->params.log_blowup=v; else if(k&&strcmp(k,"log_final_poly_len")==0)fx->params.log_final_poly_len=v; else if(k&&strcmp(k,"max_log_arity")==0)fx->params.max_log_arity=v; else if(k&&strcmp(k,"num_queries")==0)fx->params.num_queries=v; else if(k&&strcmp(k,"commit_proof_of_work_bits")==0)fx->params.commit_proof_of_work_bits=v; else if(k&&strcmp(k,"query_proof_of_work_bits")==0)fx->params.query_proof_of_work_bits=v; free(k); }
}
static void parse_proof(js_t *s,gx_t *fx){
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
static void parse_instance(js_t *s,gx_t *fx){
    js_match(s,'{'); while(!js_match(s,'}')){ if(js_peek(s,',')){s->pos++;continue;} char*k=js_read_string(s); js_match(s,':'); uint64_t v=0; js_read_u64(s,&v);
        if(k&&strcmp(k,"degree_bits")==0)fx->degree_bits=(size_t)v; else if(k&&strcmp(k,"num_quotient_chunks")==0)fx->num_quotient_chunks=(size_t)v; free(k); }
}
static void parse_commitments(js_t *s,gx_t *fx){
    js_match(s,'{'); while(!js_match(s,'}')){ if(js_peek(s,',')){s->pos++;continue;} char*k=js_read_string(s); js_match(s,':');
        if(k&&strcmp(k,"trace_commit_root_hex")==0){ char*h=js_read_string(s); hex_decode(h,fx->trace_commit.bytes,DNAC_MERKLE_DIGEST_BYTES); free(h); }
        else if(k&&strcmp(k,"quotient_commit_root_hex")==0){ char*h=js_read_string(s); hex_decode(h,fx->quotient_commit.bytes,DNAC_MERKLE_DIGEST_BYTES); free(h); }
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
        if(k&&strcmp(k,"trace_local")==0)fx->trace_local_len=parse_fp2_decimal_array(s,fx->trace_local,GXCOL);
        else if(k&&strcmp(k,"trace_next")==0){ if(js_peek(s,'[')){ fx->trace_next_len=parse_fp2_decimal_array(s,fx->trace_next,GXCOL); fx->has_trace_next=1; } else { js_skip_value(s); fx->has_trace_next=0; } }
        else if(k&&strcmp(k,"quotient_chunks")==0){ size_t c=0; js_match(s,'['); while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;} if(c<GXCHUNK)fx->quot_chunk_len[c]=parse_fp2_decimal_array(s,fx->quot_chunk[c],GXCOL); else js_skip_value(s); c++; } fx->num_quot_chunks_parsed=c; }
        else { js_skip_value(s); } free(k); }
}
static void parse_snapshot(js_t *s,gx_t *fx){
    js_match(s,'{'); while(!js_match(s,'}')){ if(js_peek(s,',')){s->pos++;continue;} char*k=js_read_string(s); js_match(s,':');
        if(k&&strcmp(k,"input_buf_hex")==0){ char*h=js_read_string(s); fx->input_buf_exp_len=hex_decode(h,fx->input_buf_exp,sizeof fx->input_buf_exp); free(h); } else { js_skip_value(s); } free(k); }
}

static void wire_proof(gx_t *fx){
    fx->proof.commit_phase_commits=fx->commits; fx->proof.num_commit_phase_commits=fx->num_commits;
    fx->proof.commit_pow_witnesses=fx->witnesses; fx->proof.num_commit_pow_witnesses=fx->num_commits;
    fx->proof.query_proofs=fx->qp; fx->proof.num_query_proofs=fx->num_queries;
    fx->proof.final_poly=fx->final_poly; fx->proof.num_final_poly=fx->num_final_poly;
    fx->proof.query_pow_witness=fx->qpow;
}

/* Build the FibonacciAir CommitmentWithOpeningPoints from derived zeta/zeta_next.
 * Domain shift is NOT wired (codec encodes only log_size; verifier derives x from
 * GENERATOR); both trace + quotient opening domains are natural, log_size=degree_bits. */
static void build_coms(gx_t *fx, gold_fp2_t zeta, gold_fp2_t zeta_next){
    /* trace commitment: 1 matrix, points (zeta, trace_local) [+ (zeta_next, trace_next)] */
    fx->trace_points[0].point=zeta; fx->trace_points[0].claimed_evals=fx->trace_local; fx->trace_points[0].num_claimed_evals=fx->trace_local_len;
    size_t np=1;
    if(fx->has_trace_next){ fx->trace_points[1].point=zeta_next; fx->trace_points[1].claimed_evals=fx->trace_next; fx->trace_points[1].num_claimed_evals=fx->trace_next_len; np=2; }
    fx->trace_matrix.domain.shift=gold_fp_from_u64(0); fx->trace_matrix.domain.shift_inverse=gold_fp_from_u64(0); fx->trace_matrix.domain.log_size=fx->degree_bits;
    fx->trace_matrix.points=fx->trace_points; fx->trace_matrix.num_points=np;
    fx->cwop[0].commitment=fx->trace_commit; fx->cwop[0].matrices=&fx->trace_matrix; fx->cwop[0].num_matrices=1;

    /* quotient commitment: num_qc matrices, each 1 point (zeta, chunk_c) */
    for(size_t c=0;c<fx->num_quot_chunks_parsed;c++){
        fx->quot_points[c].point=zeta; fx->quot_points[c].claimed_evals=fx->quot_chunk[c]; fx->quot_points[c].num_claimed_evals=fx->quot_chunk_len[c];
        fx->quot_matrix[c].domain.shift=gold_fp_from_u64(0); fx->quot_matrix[c].domain.shift_inverse=gold_fp_from_u64(0); fx->quot_matrix[c].domain.log_size=fx->degree_bits;
        fx->quot_matrix[c].points=&fx->quot_points[c]; fx->quot_matrix[c].num_points=1;
    }
    fx->cwop[1].commitment=fx->quotient_commit; fx->cwop[1].matrices=fx->quot_matrix; fx->cwop[1].num_matrices=fx->num_quot_chunks_parsed;
}

/* negatives: minimal DZKS base mutations (inner-agnostic, identical to P5) */
static void wr16(uint8_t *p,uint16_t v){ p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); }
static void wr32(uint8_t *p,uint32_t v){ for(int i=0;i<4;i++)p[i]=(uint8_t)(v>>(8*i)); }
static void wr64(uint8_t *p,uint64_t v){ for(int i=0;i<8;i++)p[i]=(uint8_t)(v>>(8*i)); }
static void emit_neg(FILE *f,int first,const char *name,int status,const uint8_t *b,size_t n){
    fprintf(f,"%s\n    {\"name\": \"%s\", \"expect_status\": %d, \"wire_hex\": \"",first?"":",",name,status); fput_hex(f,b,n); fprintf(f,"\"}");
}

int main(int argc,char **argv){
    if(argc<3){ fprintf(stderr,"usage: %s <stark_priming.json> <out>\n",argv[0]); return 2; }
    gx_t *fx=(gx_t*)calloc(1,sizeof *fx); if(!fx)return 2;
    size_t bl=0; char *blob=slurp(argv[1],&bl); if(!blob){ fprintf(stderr,"cannot read %s\n",argv[1]); return 2; }
    js_t s={blob,0,bl}; js_match(&s,'{');
    while(!js_match(&s,'}')){ if(js_peek(&s,',')){s.pos++;continue;} char*k=js_read_string(&s); if(!k)break; js_match(&s,':');
        if(k&&strcmp(k,"instance")==0)parse_instance(&s,fx);
        else if(k&&strcmp(k,"fri_params")==0)parse_params(&s,fx);
        else if(k&&strcmp(k,"proof_serde")==0)parse_proof(&s,fx);
        else if(k&&strcmp(k,"commitments")==0)parse_commitments(&s,fx);
        else if(k&&strcmp(k,"public_values")==0)parse_public_values(&s,fx);
        else if(k&&strcmp(k,"challenges")==0)parse_challenges(&s,fx);
        else if(k&&strcmp(k,"opened_values")==0)parse_opened(&s,fx);
        else if(k&&strcmp(k,"transcript_snapshot_at_verify_fri_entry")==0)parse_snapshot(&s,fx);
        else if(k&&strcmp(k,"init_state_hex")==0){ char*h=js_read_string(&s); fx->init_state_len=hex_decode(h,fx->init_state,sizeof fx->init_state); free(h); }
        else js_skip_value(&s);
        free(k);
    }
    free(blob);
    wire_proof(fx);

    /* ---- priming (P3 helper) ---- */
    dnac_stark_priming_input_t in; memset(&in,0,sizeof in);
    in.degree_bits=fx->degree_bits; in.is_zk=0; in.preprocessed_width=0;
    in.trace_commit=fx->trace_commit; in.quotient_commit=fx->quotient_commit;
    in.public_values=fx->public_values; in.num_public_values=fx->num_public_values;
    in.trace_local=fx->trace_local; in.trace_local_len=fx->trace_local_len;
    in.trace_next=fx->has_trace_next?fx->trace_next:NULL; in.trace_next_len=fx->trace_next_len;
    const gold_fp2_t *qcptr[GXCHUNK]; size_t qclen[GXCHUNK];
    for(size_t c=0;c<fx->num_quot_chunks_parsed;c++){ qcptr[c]=fx->quot_chunk[c]; qclen[c]=fx->quot_chunk_len[c]; }
    in.quotient_chunks=qcptr; in.quotient_chunk_lens=qclen; in.num_quotient_chunks=fx->num_quot_chunks_parsed;

    dnac_transcript_t *t=dnac_transcript_init(fx->init_state,fx->init_state_len);
    if(!t){ fprintf(stderr,"transcript init failed\n"); return 1; }
    dnac_stark_priming_out_t out; memset(&out,0,sizeof out);
    if(dnac_stark_prime_transcript(t,&in,&out)!=DNAC_STARK_PRIMING_OK){ fprintf(stderr,"priming failed\n"); return 1; }
    if(!gold_fp2_eq(out.alpha,fx->alpha_exp)||!gold_fp2_eq(out.zeta,fx->zeta_exp)||!gold_fp2_eq(out.zeta_next,fx->zeta_next_exp)){
        fprintf(stderr,"GATE: priming alpha/zeta/zeta_next != stark_priming.json challenges\n"); return 1;
    }

    /* ---- build coms (derived zeta/zeta_next), encode DZKF, decode, VERIFY (gate) ---- */
    build_coms(fx,out.zeta,out.zeta_next);
    uint8_t *dzkf=NULL; size_t dzkf_len=0;
    if(dnac_fri_proof_encode(&fx->params,&fx->proof,fx->cwop,2,&dzkf,&dzkf_len)!=DNAC_FRI_CODEC_OK){ fprintf(stderr,"DZKF encode failed\n"); return 1; }
    dnac_fri_wire_package_t *pkg=NULL;
    if(dnac_fri_proof_decode(dzkf,dzkf_len,&pkg)!=DNAC_FRI_CODEC_OK){ fprintf(stderr,"DZKF decode failed\n"); return 1; }
    size_t nc=0; const dnac_fri_commitment_with_opening_points_t *dcoms=dnac_fri_wire_commitments(pkg,&nc);
    dnac_fri_status_t fs=dnac_fri_verify(dnac_fri_wire_params(pkg),dnac_fri_wire_proof(pkg),t,dcoms,nc);
    if(fs!=DNAC_FRI_OK){
        fprintf(stderr,"GATE FAILED: dnac_fri_verify -> %d (want 0=DNAC_FRI_OK) at log_blowup=%zu log_final_poly_len=%zu num_points(trace)=%zu\n",
                (int)fs, fx->params.log_blowup, fx->params.log_final_poly_len, fx->has_trace_next?(size_t)2:(size_t)1);
        return 1;
    }
    dnac_fri_wire_free(pkg); dnac_transcript_free(t);

    /* ---- wrap DZKS + emit JSON (valid FibonacciAir inner + 8 negatives) ---- */
    uint8_t *dzks=NULL; size_t dzks_len=0;
    if(dnac_stark_proof_encode(fx->degree_bits,fx->public_values,fx->num_public_values,dzkf,dzkf_len,&dzks,&dzks_len)!=DNAC_STARK_WIRE_OK){ fprintf(stderr,"DZKS encode failed\n"); return 1; }

    /* minimal base for negative mutations */
    uint8_t *mb=NULL; size_t mbl=0; uint8_t small_inner[8]={0};
    dnac_stark_proof_encode(fx->degree_bits,fx->public_values,fx->num_public_values,small_inner,sizeof small_inner,&mb,&mbl);
    size_t pub_off=18, inner_len_off=18+8*fx->num_public_values;

    FILE *f=fopen(argv[2],"wb"); if(!f){ fprintf(stderr,"cannot write %s\n",argv[2]); return 1; }
    fprintf(f,"{\n  \"format_version\": \"1\",\n  \"scope\": \"stark_proof_wire\",\n");
    fprintf(f,"  \"spec_doc\": \"docs/plans/2026-05-30-pcs-transcript-priming-design.md \\u00a7 8\",\n");
    if(fx->has_trace_next)
        fprintf(f,"  \"note\": \"Additive DZKS wrapper around the REAL FibonacciAir DZKF FRI wire (P6). degree_bits + public_values are the FibonacciAir STARK scalars; the inner DZKF is the FibonacciAir FRI proof, GATE-verified: dnac_stark_prime_transcript -> dnac_fri_verify == DNAC_FRI_OK before this wire was written. (P5 used a placeholder V6 inner; P6 binds the real one.) base_degree_bits/preprocessed_width/zeta/zeta_next/z are NOT wired.\",\n");
    else
        fprintf(f,"  \"note\": \"Additive DZKS wrapper around the REAL SquareAir (no_next, main_next=false) DZKF FRI wire (P6 Part B). degree_bits is the SquareAir STARK scalar; public_values is empty; the inner DZKF is the SquareAir FRI proof whose trace round opens at the SINGLE point zeta (verifier.rs:420-428), GATE-verified: dnac_stark_prime_transcript -> dnac_fri_verify == DNAC_FRI_OK before this wire was written. base_degree_bits/preprocessed_width/zeta/zeta_next/z are NOT wired.\",\n");
    fprintf(f,"  \"wire_magic_hex\": \"445a4b53\", \"wire_version\": 1,\n");
    fprintf(f,"  \"gate\": {\"dnac_fri_verify\": \"DNAC_FRI_OK\", \"log_blowup\": %zu, \"log_final_poly_len\": %zu, \"trace_open_points\": %d, \"num_commitments\": 2},\n",
            fx->params.log_blowup, fx->params.log_final_poly_len, fx->has_trace_next?2:1);
    fprintf(f,"  \"valid\": {\n    \"name\": \"%s\",\n    \"expect_status\": 0,\n",
            fx->has_trace_next?"fib_stark_wrapper":"square_no_next_stark_wrapper");
    fprintf(f,"    \"degree_bits\": %zu,\n    \"public_values\": [",fx->degree_bits);
    for(size_t i=0;i<fx->num_public_values;i++) fprintf(f,"%s\"%llu\"",i?", ":"",(unsigned long long)gold_fp_to_u64(fx->public_values[i]));
    fprintf(f,"],\n    \"inner_dzkf_len\": %zu,\n    \"inner_dzkf_hex\": \"",dzkf_len); fput_hex(f,dzkf,dzkf_len);
    fprintf(f,"\",\n    \"wire_len\": %zu,\n    \"wire_hex\": \"",dzks_len); fput_hex(f,dzks,dzks_len); fprintf(f,"\"\n  },\n");

    fprintf(f,"  \"negative\": [");
    emit_neg(f,1,"truncated",2,mb,5);
    { uint8_t *m=malloc(mbl); memcpy(m,mb,mbl); m[0]=0x00; emit_neg(f,0,"bad_magic",3,m,mbl); free(m); }
    { uint8_t *m=malloc(mbl); memcpy(m,mb,mbl); wr16(m+4,2); emit_neg(f,0,"bad_version",4,m,mbl); free(m); }
    { uint8_t *m=malloc(mbl); memcpy(m,mb,mbl); wr32(m+6,(uint32_t)(mbl-1)); emit_neg(f,0,"total_len_mismatch",7,m,mbl); free(m); }
    { uint8_t m[30]; memset(m,0,sizeof m); m[0]='D';m[1]='Z';m[2]='K';m[3]='S'; wr16(m+4,1); wr32(m+6,30); wr32(m+10,3); wr32(m+14,1); wr64(m+18,0xFFFFFFFFFFFFFFFFULL); wr32(m+26,0); emit_neg(f,0,"noncanonical_public_value",5,m,sizeof m); }
    { uint8_t m[18]; memset(m,0,sizeof m); m[0]='D';m[1]='Z';m[2]='K';m[3]='S'; wr16(m+4,1); wr32(m+6,18); wr32(m+10,3); wr32(m+14,0xFFFFFFFFu); emit_neg(f,0,"public_values_length_overflow",6,m,sizeof m); }
    { uint8_t *m=malloc(mbl); memcpy(m,mb,mbl); wr32(m+inner_len_off,0xFFFFFFFFu); emit_neg(f,0,"inner_dzkf_len_overflow",6,m,mbl); free(m); }
    { uint8_t *m=malloc(mbl+1); memcpy(m,mb,mbl); m[mbl]=0xAA; wr32(m+6,(uint32_t)(mbl+1)); emit_neg(f,0,"trailing_bytes",8,m,mbl+1); free(m); }
    fprintf(f,"\n  ]\n}\n");
    fclose(f);
    (void)pub_off;

    fprintf(stderr,"wrote %s (%s DZKS wire_len=%zu, inner DZKF=%zu B; GATE dnac_fri_verify=DNAC_FRI_OK; log_blowup=%zu, log_final_poly_len=%zu, trace points=%d, 2 commitments)\n",
            argv[2], fx->has_trace_next?"FibonacciAir":"SquareAir(no_next)", dzks_len, dzkf_len, fx->params.log_blowup, fx->params.log_final_poly_len, fx->has_trace_next?2:1);
    free(dzkf); free(dzks); free(mb); free(fx);
    return 0;
}
