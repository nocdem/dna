/**
 * @file gen_fri_proof_wire.c
 * @brief Build-time generator for tools/vectors/fri_proof_wire.json.
 *
 * Parses the LOCKED Plonky3-grounded vectors fri_verifier_valid.json (V6, with
 * its primed seed from fri_verifier_transcript_milestones.json) and
 * fri_verifier_rollin.json (roll-in, seed embedded), rebuilds the C structs the
 * FRI verifier consumes, encodes them with the REAL codec
 * (dnac_fri_proof_encode), and emits the wire vector: V6 + roll-in wire bytes
 * (hex) + per-case primed seed (hex) + decoded summary + the negative malformed
 * codec cases.
 *
 * The C codec is the single source of truth for the wire bytes (no Rust
 * duplication); correctness is anchored by the C replay test:
 * decode(wire) -> dnac_fri_verify -> DNAC_FRI_OK. Deterministic: same inputs ->
 * byte-identical output (regenerate-and-compare). Negative cases are crafted by
 * deterministic mutation at fixed offsets / minimal synthetic wires.
 *
 * Usage: gen_fri_proof_wire <valid.json> <transcript_milestones.json>
 *                           <rollin.json> <out fri_proof_wire.json>
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fri_proof_codec.h"
#include "fri_verifier.h"
#include "field_goldilocks.h"

/* ===== JSON scanner (same idiom as the FRI verifier tests) ===== */
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
static void to_hex(const uint8_t *b,size_t n,char *out){ static const char *H="0123456789abcdef"; for(size_t i=0;i<n;i++){ out[2*i]=H[b[i]>>4]; out[2*i+1]=H[b[i]&0xF]; } out[2*n]='\0'; }
static void put_u64_le(uint8_t *p,uint64_t v){ for(int i=0;i<8;i++)p[i]=(uint8_t)(v>>(8*i)); }

/* ===== serde value parsers (same shapes as the FRI verifier vectors) ===== */
static int read_u64_array(js_t *s,uint64_t *out,int cap){ int n=0; js_match(s,'['); while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;} uint64_t v; if(!js_read_u64(s,&v))return -1; if(n<cap)out[n]=v; n++; } return n; }
static void parse_lanes_digest(js_t *s,uint8_t out[64]){ uint64_t l[8]={0}; read_u64_array(s,l,8); for(int i=0;i<8;i++)put_u64_le(out+i*8,l[i]); }
static void parse_commit_digest(js_t *s,uint8_t out[64]){
    js_match(s,'{'); while(!js_match(s,'}')){ if(js_peek(s,',')){s->pos++;continue;} char*k=js_read_string(s); js_match(s,':');
        if(k&&strcmp(k,"cap")==0){ js_match(s,'['); parse_lanes_digest(s,out); while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;} js_skip_value(s);} } else js_skip_value(s); free(k); }
}
static uint64_t parse_base_obj(js_t *s){ uint64_t r=0; js_match(s,'{'); while(!js_match(s,'}')){ if(js_peek(s,',')){s->pos++;continue;} char*k=js_read_string(s); js_match(s,':'); if(k&&strcmp(k,"value")==0)js_read_u64(s,&r); else js_skip_value(s); free(k);} return r; }
static gold_fp2_t parse_fp2_wrapped(js_t *s){
    uint64_t comps[2]={0,0}; int n=0; js_match(s,'{');
    while(!js_match(s,'}')){ if(js_peek(s,',')){s->pos++;continue;} char*k=js_read_string(s); js_match(s,':');
        if(k&&strcmp(k,"value")==0){ js_match(s,'['); while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;} uint64_t bv=parse_base_obj(s); if(n<2)comps[n]=bv; n++; } } else js_skip_value(s); free(k); }
    return gold_fp2_new(gold_fp_from_u64(comps[0]),gold_fp_from_u64(comps[1]));
}
static gold_fp2_t parse_fp2_decimal(js_t *s){
    uint64_t c0=0,c1=0; js_match(s,'{');
    while(!js_match(s,'}')){ if(js_peek(s,',')){s->pos++;continue;} char*k=js_read_string(s); js_match(s,':'); char*v=js_peek(s,'"')?js_read_string(s):NULL;
        if(v&&k&&strcmp(k,"c0_decimal")==0)c0=strtoull(v,NULL,10); else if(v&&k&&strcmp(k,"c1_decimal")==0)c1=strtoull(v,NULL,10); else if(!v)js_skip_value(s); free(v); free(k); }
    return gold_fp2_new(gold_fp_from_u64(c0),gold_fp_from_u64(c1));
}

/* ===== storage (multi-commitment / multi-batch superset) ===== */
#define GXQ 4
#define GXB 4
#define GXR 12
#define GXCOL 16
#define GXSIB 16

typedef struct {
    dnac_fri_params_t params;

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

    dnac_merkle_digest_t commitment[GXB];
    gold_fp2_t           claimed[GXB][GXCOL]; size_t num_claimed[GXB];
    dnac_fri_opening_point_t point[GXB];
    dnac_fri_matrix_openings_t matrix[GXB];
    dnac_fri_commitment_with_opening_points_t cwop[GXB];
    uint64_t domain_log_size[GXB];
    size_t num_commitments;
    gold_fp2_t zeta;

    uint8_t seed[256]; size_t seed_len;
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
/* opened_values_serde: array of batches, each [[ [fp2..] ]] */
static void parse_opened_values(js_t *s,gx_t *fx){
    size_t b=0; js_match(s,'[');
    while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;}
        js_match(s,'['); js_match(s,'['); js_match(s,'['); size_t nc=0;
        while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;} gold_fp2_t fv=parse_fp2_wrapped(s); if(b<GXB&&nc<GXCOL)fx->claimed[b][nc]=fv; nc++; }
        if(b<GXB)fx->num_claimed[b]=nc;
        while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;} js_skip_value(s);} while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;} js_skip_value(s);} b++; }
}
/* fixture: log_degree (single) OR matrices[{log_degree}] */
static void parse_fixture(js_t *s,gx_t *fx){
    js_match(s,'{'); while(!js_match(s,'}')){ if(js_peek(s,',')){s->pos++;continue;} char*k=js_read_string(s); js_match(s,':');
        if(k&&strcmp(k,"log_degree")==0){ uint64_t v=0; js_read_u64(s,&v); fx->domain_log_size[0]=v; }
        else if(k&&strcmp(k,"matrices")==0){ size_t mi=0; js_match(s,'['); while(!js_match(s,']')){ if(js_peek(s,',')){s->pos++;continue;} uint64_t ld=0; js_match(s,'{'); while(!js_match(s,'}')){ if(js_peek(s,',')){s->pos++;continue;} char*mk=js_read_string(s); js_match(s,':'); if(mk&&strcmp(mk,"log_degree")==0)js_read_u64(s,&ld); else js_skip_value(s); free(mk);} if(mi<GXB)fx->domain_log_size[mi]=ld; mi++; } }
        else { js_skip_value(s); }
        free(k);
    }
}
static void parse_primed(js_t *s,gx_t *fx){
    js_match(s,'{'); while(!js_match(s,'}')){ if(js_peek(s,',')){s->pos++;continue;} char*k=js_read_string(s); js_match(s,':');
        if(k&&strcmp(k,"input_buf_hex")==0){ char*h=js_read_string(s); if(h){ fx->seed_len=hex_decode(h,fx->seed,sizeof fx->seed); free(h);} } else js_skip_value(s); free(k); }
}
/* milestones.json: milestones[0].transcript.input_buf_hex -> seed */
static void load_seed_from_milestones(const char *path,gx_t *fx){
    size_t bl=0; char *blob=slurp(path,&bl); if(!blob)return; js_t s={blob,0,bl}; js_match(&s,'{');
    while(!js_match(&s,'}')){ if(js_peek(&s,',')){s.pos++;continue;} char*k=js_read_string(&s); js_match(&s,':');
        if(k&&strcmp(k,"milestones")==0){ js_match(&s,'['); js_match(&s,'{');
            while(!js_match(&s,'}')){ if(js_peek(&s,',')){s.pos++;continue;} char*mk=js_read_string(&s); js_match(&s,':');
                if(mk&&strcmp(mk,"transcript")==0){ js_match(&s,'{'); while(!js_match(&s,'}')){ if(js_peek(&s,',')){s.pos++;continue;} char*tk=js_read_string(&s); js_match(&s,':'); if(tk&&strcmp(tk,"input_buf_hex")==0){ char*h=js_read_string(&s); if(h){fx->seed_len=hex_decode(h,fx->seed,sizeof fx->seed); free(h);} } else js_skip_value(&s); free(tk);} } else js_skip_value(&s); free(mk); }
            while(!js_match(&s,']')){ if(js_peek(&s,',')){s.pos++;continue;} js_skip_value(&s);} }
        else { js_skip_value(&s); }
        free(k);
    }
    free(blob);
}

/* Wire the dnac proof + cwop pointers after parsing. */
static void wire_structs(gx_t *fx){
    fx->proof.commit_phase_commits=fx->commits; fx->proof.num_commit_phase_commits=fx->num_commits;
    fx->proof.commit_pow_witnesses=fx->witnesses; fx->proof.num_commit_pow_witnesses=fx->num_commits;
    fx->proof.query_proofs=fx->qp; fx->proof.num_query_proofs=fx->num_queries;
    fx->proof.final_poly=fx->final_poly; fx->proof.num_final_poly=fx->num_final_poly;
    fx->proof.query_pow_witness=fx->qpow;
    for(size_t b=0;b<fx->num_commitments;b++){
        fx->point[b].point=fx->zeta; fx->point[b].claimed_evals=fx->claimed[b]; fx->point[b].num_claimed_evals=fx->num_claimed[b];
        fx->matrix[b].domain.shift=gold_fp_from_u64(0); fx->matrix[b].domain.shift_inverse=gold_fp_from_u64(0);
        fx->matrix[b].domain.log_size=(size_t)fx->domain_log_size[b]; fx->matrix[b].points=&fx->point[b]; fx->matrix[b].num_points=1;
        fx->cwop[b].commitment=fx->commitment[b]; fx->cwop[b].matrices=&fx->matrix[b]; fx->cwop[b].num_matrices=1;
    }
}

/* Load a vector file into fx (handles both valid.json and rollin.json formats).
 * If seed is not embedded (valid.json), caller supplies milestones path. */
static int load_vector(const char *path,gx_t *fx){
    memset(fx,0,sizeof *fx); fx->num_commitments=0;
    size_t bl=0; char *blob=slurp(path,&bl); if(!blob){ fprintf(stderr,"cannot read %s\n",path); return 0; }
    js_t s={blob,0,bl}; js_match(&s,'{');
    while(!js_match(&s,'}')){ if(js_peek(&s,',')){s.pos++;continue;} char*k=js_read_string(&s); js_match(&s,':');
        if(k&&strcmp(k,"fri_params")==0)parse_params(&s,fx);
        else if(k&&strcmp(k,"proof")==0)parse_proof(&s,fx);
        else if(k&&strcmp(k,"commitment_serde")==0){ parse_commit_digest(&s,fx->commitment[0].bytes); if(fx->num_commitments<1)fx->num_commitments=1; }
        else if(k&&strcmp(k,"commitments_serde")==0){ size_t n=0; js_match(&s,'['); while(!js_match(&s,']')){ if(js_peek(&s,',')){s.pos++;continue;} if(n<GXB)parse_commit_digest(&s,fx->commitment[n].bytes); else js_skip_value(&s); n++; } fx->num_commitments=n; }
        else if(k&&strcmp(k,"opened_values_serde")==0)parse_opened_values(&s,fx);
        else if(k&&strcmp(k,"transcript_zeta_fp2")==0)fx->zeta=parse_fp2_decimal(&s);
        else if(k&&strcmp(k,"fixture")==0)parse_fixture(&s,fx);
        else if(k&&strcmp(k,"primed_transcript")==0)parse_primed(&s,fx);
        else { js_skip_value(&s); }
        free(k);
    }
    free(blob);
    wire_structs(fx);
    return 1;
}

/* ===== synthetic minimal-wire builder for deep-offset negative cases ===== */
typedef struct { uint8_t b[512]; size_t n; } sb_t;
static void sb_u8(sb_t *w,uint8_t v){ w->b[w->n++]=v; }
static void sb_u16(sb_t *w,uint16_t v){ sb_u8(w,(uint8_t)v); sb_u8(w,(uint8_t)(v>>8)); }
static void sb_u32(sb_t *w,uint32_t v){ for(int i=0;i<4;i++)sb_u8(w,(uint8_t)(v>>(8*i))); }
static void sb_u64(sb_t *w,uint64_t v){ for(int i=0;i<8;i++)sb_u8(w,(uint8_t)(v>>(8*i))); }
static void sb_header(sb_t *w){ sb_u8(w,DNAC_FRI_WIRE_MAGIC0); sb_u8(w,DNAC_FRI_WIRE_MAGIC1); sb_u8(w,DNAC_FRI_WIRE_MAGIC2); sb_u8(w,DNAC_FRI_WIRE_MAGIC3); sb_u16(w,(uint16_t)DNAC_FRI_WIRE_VERSION); sb_u32(w,0); }
static void sb_params(sb_t *w){ for(int i=0;i<6;i++)sb_u32(w,1); } /* 6 small params */
static void sb_patch_total(sb_t *w){ uint32_t tl=(uint32_t)w->n; for(int i=0;i<4;i++)w->b[6+i]=(uint8_t)(tl>>(8*i)); }

/* ===== JSON emit helpers ===== */
static void emit_hex_field(FILE *f,const char *key,const uint8_t *b,size_t n){
    char *h=(char*)malloc(2*n+1); to_hex(b,n,h); fprintf(f,"\"%s\": \"%s\"",key,h); free(h);
}

int main(int argc,char **argv){
    if(argc<5){ fprintf(stderr,"usage: %s <valid.json> <milestones.json> <rollin.json> <out>\n",argv[0]); return 2; }
    const char *valid_path=argv[1], *miles_path=argv[2], *rollin_path=argv[3], *out_path=argv[4];

    /* --- V6 --- */
    gx_t *v6=(gx_t*)calloc(1,sizeof *v6); if(!v6)return 2;
    if(!load_vector(valid_path,v6))return 1;
    load_seed_from_milestones(miles_path,v6);
    uint8_t *v6_wire=NULL; size_t v6_len=0;
    if(dnac_fri_proof_encode(&v6->params,&v6->proof,v6->cwop,v6->num_commitments,&v6_wire,&v6_len)!=DNAC_FRI_CODEC_OK){ fprintf(stderr,"V6 encode failed\n"); return 1; }

    /* --- roll-in --- */
    gx_t *ro=(gx_t*)calloc(1,sizeof *ro); if(!ro)return 2;
    if(!load_vector(rollin_path,ro))return 1;
    uint8_t *ro_wire=NULL; size_t ro_len=0;
    if(dnac_fri_proof_encode(&ro->params,&ro->proof,ro->cwop,ro->num_commitments,&ro_wire,&ro_len)!=DNAC_FRI_CODEC_OK){ fprintf(stderr,"rollin encode failed\n"); return 1; }

    /* --- negative cases (deterministic) --- */
    /* 1. truncated header: 5 bytes (magic + 1 version byte) -> TRUNCATED */
    uint8_t neg_trunc[5]={DNAC_FRI_WIRE_MAGIC0,DNAC_FRI_WIRE_MAGIC1,DNAC_FRI_WIRE_MAGIC2,DNAC_FRI_WIRE_MAGIC3,(uint8_t)DNAC_FRI_WIRE_VERSION};
    /* 2. bad magic: V6 copy, byte 0 zeroed -> BAD_MAGIC */
    uint8_t *neg_magic=(uint8_t*)malloc(v6_len); memcpy(neg_magic,v6_wire,v6_len); neg_magic[0]=0x00;
    /* 3. bad version: V6 copy, version (offset 4..5) = 0x0002 -> BAD_VERSION */
    uint8_t *neg_ver=(uint8_t*)malloc(v6_len); memcpy(neg_ver,v6_wire,v6_len); neg_ver[4]=0x02; neg_ver[5]=0x00;
    /* 4. noncanonical: synthetic wire, query_pow_witness = p -> NONCANONICAL */
    sb_t s_nc; s_nc.n=0; sb_header(&s_nc); sb_params(&s_nc);
        sb_u32(&s_nc,0); /* commit_phase_commits count */
        sb_u32(&s_nc,0); /* commit_pow_witnesses count */
        sb_u32(&s_nc,0); /* final_poly count */
        sb_u64(&s_nc,GOLDILOCKS_P); /* query_pow_witness = p (noncanonical) */
        sb_patch_total(&s_nc);
    /* 5. length overflow: synthetic, commit_phase_commits count = 0xFFFFFFFF -> LENGTH_OVERFLOW */
    sb_t s_lo; s_lo.n=0; sb_header(&s_lo); sb_params(&s_lo); sb_u32(&s_lo,0xFFFFFFFFu); sb_patch_total(&s_lo);
    /* 6. inconsistent length: V6 copy, total_len field (offset 6) = len-1 -> INCONSISTENT_LENGTH */
    uint8_t *neg_incon=(uint8_t*)malloc(v6_len); memcpy(neg_incon,v6_wire,v6_len);
        { uint32_t bad=(uint32_t)(v6_len-1); for(int i=0;i<4;i++)neg_incon[6+i]=(uint8_t)(bad>>(8*i)); }
    /* 7. bad merkle depth: synthetic, first opening_proof depth = 0xFFFFFFFF -> BAD_DEPTH */
    sb_t s_bd; s_bd.n=0; sb_header(&s_bd); sb_params(&s_bd);
        sb_u32(&s_bd,0); /* commits */ sb_u32(&s_bd,0); /* witnesses */ sb_u32(&s_bd,0); /* final_poly */
        sb_u64(&s_bd,0); /* query_pow_witness = 0 (canonical) */
        sb_u32(&s_bd,1); /* query_proofs count */
        sb_u32(&s_bd,1); /* input_proof count */
        sb_u32(&s_bd,0); /* batch num_matrices count = 0 */
        sb_u32(&s_bd,0xFFFFFFFFu); /* opening_proof depth */
        sb_patch_total(&s_bd);
    /* 8. trailing bytes: V6 copy + 1 byte, total_len = len+1 -> TRAILING (pos finishes early) */
    size_t neg_tr_len=v6_len+1; uint8_t *neg_tr=(uint8_t*)malloc(neg_tr_len); memcpy(neg_tr,v6_wire,v6_len); neg_tr[v6_len]=0xAA;
        { uint32_t nl=(uint32_t)neg_tr_len; for(int i=0;i<4;i++)neg_tr[6+i]=(uint8_t)(nl>>(8*i)); }

    /* --- emit JSON --- */
    FILE *f=fopen(out_path,"wb"); if(!f){ fprintf(stderr,"cannot write %s\n",out_path); return 1; }
    fprintf(f,"{\n");
    fprintf(f,"  \"format_version\": \"1\",\n");
    fprintf(f,"  \"plonky3_commit\": \"82cfad73cd734d37a0d51953094f970c531817ec\",\n");
    fprintf(f,"  \"scope\": \"fri_proof_wire\",\n");
    fprintf(f,"  \"spec_doc\": \"docs/plans/2026-05-29-fri-proof-wire-codec-design.md\",\n");
    fprintf(f,"  \"note\": \"Wire bytes produced by the C codec dnac_fri_proof_encode from the locked Plonky3-grounded V6 + roll-in fixtures. Correctness anchor: decode(wire) -> dnac_fri_verify -> DNAC_FRI_OK. DNAC wire format (magic DZKF + u16 version + u32 total_len; LE; canonical u64 Goldilocks; fp2 c0|c1; digest 64B; u32 length prefixes).\",\n");
    fprintf(f,"  \"wire_magic_hex\": \"445a4b46\", \"wire_version\": 1,\n");

    fprintf(f,"  \"cases\": [\n");
    /* V6 */
    fprintf(f,"    {\n      \"name\": \"v6_valid\",\n      \"expect_codec\": 0, \"expect_fri\": 0,\n");
    fprintf(f,"      \"wire_len\": %zu,\n      ",v6_len); emit_hex_field(f,"wire_hex",v6_wire,v6_len); fprintf(f,",\n      ");
    emit_hex_field(f,"seed_hex",v6->seed,v6->seed_len); fprintf(f,",\n");
    fprintf(f,"      \"summary\": {\"num_commitments\": %zu, \"num_commit_phase_commits\": %zu, \"num_query_proofs\": %zu, \"num_final_poly\": %zu, \"domain_log_sizes\": [%llu]}\n    },\n",
        v6->num_commitments,v6->num_commits,v6->num_queries,v6->num_final_poly,(unsigned long long)v6->domain_log_size[0]);
    /* roll-in */
    fprintf(f,"    {\n      \"name\": \"rollin\",\n      \"expect_codec\": 0, \"expect_fri\": 0,\n");
    fprintf(f,"      \"wire_len\": %zu,\n      ",ro_len); emit_hex_field(f,"wire_hex",ro_wire,ro_len); fprintf(f,",\n      ");
    emit_hex_field(f,"seed_hex",ro->seed,ro->seed_len); fprintf(f,",\n");
    fprintf(f,"      \"summary\": {\"num_commitments\": %zu, \"num_commit_phase_commits\": %zu, \"num_query_proofs\": %zu, \"num_final_poly\": %zu, \"domain_log_sizes\": [%llu, %llu]}\n    }\n",
        ro->num_commitments,ro->num_commits,ro->num_queries,ro->num_final_poly,(unsigned long long)ro->domain_log_size[0],(unsigned long long)ro->domain_log_size[1]);
    fprintf(f,"  ],\n");

    fprintf(f,"  \"negative\": [\n");
    #define NEG(nm,buf,len,code) do{ fprintf(f,"    {\"name\": \"%s\", \"expect_codec\": %d, ",nm,code); emit_hex_field(f,"wire_hex",buf,len); fprintf(f,"}"); }while(0)
    NEG("truncated_header",neg_trunc,sizeof neg_trunc,DNAC_FRI_CODEC_ERR_TRUNCATED); fprintf(f,",\n");
    NEG("bad_magic",neg_magic,v6_len,DNAC_FRI_CODEC_ERR_BAD_MAGIC); fprintf(f,",\n");
    NEG("bad_version",neg_ver,v6_len,DNAC_FRI_CODEC_ERR_BAD_VERSION); fprintf(f,",\n");
    NEG("noncanonical_goldilocks",s_nc.b,s_nc.n,DNAC_FRI_CODEC_ERR_NONCANONICAL); fprintf(f,",\n");
    NEG("length_overflow",s_lo.b,s_lo.n,DNAC_FRI_CODEC_ERR_LENGTH_OVERFLOW); fprintf(f,",\n");
    NEG("inconsistent_length",neg_incon,v6_len,DNAC_FRI_CODEC_ERR_INCONSISTENT_LENGTH); fprintf(f,",\n");
    NEG("bad_merkle_depth",s_bd.b,s_bd.n,DNAC_FRI_CODEC_ERR_BAD_DEPTH); fprintf(f,",\n");
    NEG("trailing_bytes",neg_tr,neg_tr_len,DNAC_FRI_CODEC_ERR_TRAILING); fprintf(f,"\n");
    #undef NEG
    fprintf(f,"  ]\n}\n");
    fclose(f);

    fprintf(stderr,"wrote %s (V6 wire %zu B, roll-in wire %zu B, 8 negative cases)\n",out_path,v6_len,ro_len);
    free(v6_wire); free(ro_wire); free(neg_magic); free(neg_ver); free(neg_incon); free(neg_tr); free(v6); free(ro);
    return 0;
}
