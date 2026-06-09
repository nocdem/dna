/**
 * @file test_fri_proof_codec.c
 * @brief FRI proof wire codec replay — roundtrip + negative malformed cases.
 *
 * Consumes tools/vectors/fri_proof_wire.json (wire bytes produced by the C codec
 * from the locked Plonky3-grounded V6 + roll-in fixtures). Asserts:
 *
 *   POSITIVE (v6_valid, rollin):
 *     - dnac_fri_proof_decode(wire) == DNAC_FRI_CODEC_OK
 *     - dnac_fri_verify(decoded, transcript-from-seed) == DNAC_FRI_OK
 *     - dnac_fri_proof_encode(decoded) reproduces the ORIGINAL wire byte-for-byte
 *     - dnac_fri_verify_wire(wire, transcript) == OK + DNAC_FRI_OK (wrapper)
 *
 *   NEGATIVE (8 malformed wires):
 *     - dnac_fri_proof_decode returns the expected DNAC_FRI_CODEC_ERR_* code
 *     - no package is leaked (out_pkg stays NULL on error)
 *     - no crash (and, under ASan/valgrind, no OOB / no leak)
 *
 * Plus: dnac_fri_wire_free(NULL) is a safe no-op.
 *
 * The codec does NOT change dnac_fri_status_t or FRI verifier semantics; the
 * end-to-end DNAC_FRI_OK on the decoded structs is the value-fidelity anchor.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fri_proof_codec.h"

/* ===== minimal JSON scanner ===== */
typedef struct { const char *src; size_t pos; size_t len; } js_t;
static void js_skip_ws(js_t *s){ while(s->pos<s->len){ char c=s->src[s->pos]; if(c==' '||c=='\t'||c=='\n'||c=='\r')s->pos++; else return; } }
static int  js_peek(js_t *s,char c){ js_skip_ws(s); return s->pos<s->len && s->src[s->pos]==c; }
static int  js_match(js_t *s,char c){ js_skip_ws(s); if(s->pos<s->len&&s->src[s->pos]==c){ s->pos++; return 1; } return 0; }
static char *js_read_string(js_t *s){
    js_skip_ws(s);
    if(s->pos>=s->len||s->src[s->pos]!='"'){ return NULL; }
    s->pos++;
    size_t start=s->pos;
    while(s->pos<s->len&&s->src[s->pos]!='"')s->pos++;
    if(s->pos>=s->len){ return NULL; }
    size_t n=s->pos-start; s->pos++;
    char *o=(char*)malloc(n+1); if(!o){ return NULL; }
    memcpy(o,s->src+start,n); o[n]='\0'; return o;
}
static int js_read_i64(js_t *s,long long *out){
    js_skip_ws(s);
    if(s->pos>=s->len){ return 0; }
    char *e=NULL; long long v=strtoll(s->src+s->pos,&e,10);
    if(e==s->src+s->pos){ return 0; }
    s->pos=(size_t)(e-s->src); *out=v; return 1;
}
static int js_skip_value(js_t *s);
static int js_skip_object(js_t *s){
    if(!js_match(s,'{')){ return 0; }
    while(1){
        if(js_match(s,'}')){ return 1; }
        if(js_peek(s,',')){ s->pos++; continue; }
        char*k=js_read_string(s); if(!k){ return 0; }
        free(k);
        if(!js_match(s,':')){ return 0; }
        if(!js_skip_value(s)){ return 0; }
    }
}
static int js_skip_array(js_t *s){
    if(!js_match(s,'[')){ return 0; }
    while(1){
        if(js_match(s,']')){ return 1; }
        if(js_peek(s,',')){ s->pos++; continue; }
        if(!js_skip_value(s)){ return 0; }
    }
}
static int js_skip_value(js_t *s){
    js_skip_ws(s);
    if(s->pos>=s->len){ return 0; }
    char c=s->src[s->pos];
    if(c=='{'){ return js_skip_object(s); }
    if(c=='['){ return js_skip_array(s); }
    if(c=='"'){ char*t=js_read_string(s); if(!t){ return 0; } free(t); return 1; }
    if(c=='t'){ s->pos+=4; return 1; }
    if(c=='f'){ s->pos+=5; return 1; }
    if(c=='n'){ s->pos+=4; return 1; }
    while(s->pos<s->len){ char d=s->src[s->pos]; if((d>='0'&&d<='9')||d=='-'||d=='+'||d=='.'||d=='e'||d=='E')s->pos++; else break; }
    return 1;
}
static char *slurp(const char *path,size_t *out_len){
    FILE *fp=fopen(path,"rb"); if(!fp){ return NULL; }
    fseek(fp,0,SEEK_END); long sz=ftell(fp); fseek(fp,0,SEEK_SET);
    if(sz<0){ fclose(fp); return NULL; }
    char *b=(char*)malloc((size_t)sz+1); if(!b){ fclose(fp); return NULL; }
    size_t got=fread(b,1,(size_t)sz,fp); fclose(fp); b[got]='\0'; *out_len=got; return b;
}
static int hexnib(char c){ if(c>='0'&&c<='9')return c-'0'; if(c>='a'&&c<='f')return c-'a'+10; if(c>='A'&&c<='F')return c-'A'+10; return -1; }
/* decode hex string into a freshly malloc'd buffer; returns buffer + sets *out_len */
static uint8_t *hex_to_buf(const char *hex,size_t *out_len){
    size_t hl=strlen(hex); if(hl%2){ return NULL; }
    size_t n=hl/2; uint8_t *b=(uint8_t*)malloc(n?n:1);
    if(!b){ return NULL; }
    for(size_t i=0;i<n;i++){ int hi=hexnib(hex[2*i]),lo=hexnib(hex[2*i+1]); if(hi<0||lo<0){ free(b); return NULL; } b[i]=(uint8_t)((hi<<4)|lo); }
    *out_len=n; return b;
}

/* ===== parsed cases ===== */
#define MAXCASE 4
#define MAXNEG  16
typedef struct { char name[64]; uint8_t *wire; size_t wire_len; uint8_t *seed; size_t seed_len; int expect_codec; int expect_fri; } pcase_t;
typedef struct { char name[64]; uint8_t *wire; size_t wire_len; int expect_codec; } pneg_t;

static pcase_t g_cases[MAXCASE]; static int g_ncases=0;
static pneg_t  g_negs[MAXNEG];   static int g_nnegs=0;

static void parse_case_obj(js_t *s){
    pcase_t c; memset(&c,0,sizeof c);
    js_match(s,'{');
    while(!js_match(s,'}')){
        if(js_peek(s,',')){ s->pos++; continue; }
        char *k=js_read_string(s); js_match(s,':');
        if(k&&strcmp(k,"name")==0){ char*v=js_read_string(s); if(v){ strncpy(c.name,v,sizeof c.name-1); free(v);} }
        else if(k&&strcmp(k,"expect_codec")==0){ long long v=0; js_read_i64(s,&v); c.expect_codec=(int)v; }
        else if(k&&strcmp(k,"expect_fri")==0){ long long v=0; js_read_i64(s,&v); c.expect_fri=(int)v; }
        else if(k&&strcmp(k,"wire_hex")==0){ char*v=js_read_string(s); if(v){ c.wire=hex_to_buf(v,&c.wire_len); free(v);} }
        else if(k&&strcmp(k,"seed_hex")==0){ char*v=js_read_string(s); if(v){ c.seed=hex_to_buf(v,&c.seed_len); free(v);} }
        else { js_skip_value(s); }
        free(k);
    }
    if(g_ncases<MAXCASE) g_cases[g_ncases++]=c;
}
static void parse_neg_obj(js_t *s){
    pneg_t c; memset(&c,0,sizeof c);
    js_match(s,'{');
    while(!js_match(s,'}')){
        if(js_peek(s,',')){ s->pos++; continue; }
        char *k=js_read_string(s); js_match(s,':');
        if(k&&strcmp(k,"name")==0){ char*v=js_read_string(s); if(v){ strncpy(c.name,v,sizeof c.name-1); free(v);} }
        else if(k&&strcmp(k,"expect_codec")==0){ long long v=0; js_read_i64(s,&v); c.expect_codec=(int)v; }
        else if(k&&strcmp(k,"wire_hex")==0){ char*v=js_read_string(s); if(v){ c.wire=hex_to_buf(v,&c.wire_len); free(v);} }
        else { js_skip_value(s); }
        free(k);
    }
    if(g_nnegs<MAXNEG) g_negs[g_nnegs++]=c;
}

int main(int argc,char **argv){
    if(argc<2){ fprintf(stderr,"usage: %s <fri_proof_wire.json>\n",argv[0]); return 2; }
    printf("============================================================\n");
    printf("FRI proof wire codec — roundtrip + negative cases\n");
    printf("============================================================\n");

    size_t blen=0; char *blob=slurp(argv[1],&blen);
    if(!blob){ fprintf(stderr,"cannot read %s\n",argv[1]); return 2; }
    js_t s={blob,0,blen};
    js_match(&s,'{');
    while(!js_match(&s,'}')){
        if(js_peek(&s,',')){ s.pos++; continue; }
        char *k=js_read_string(&s); js_match(&s,':');
        if(k&&strcmp(k,"cases")==0){ js_match(&s,'['); while(!js_match(&s,']')){ if(js_peek(&s,',')){ s.pos++; continue; } parse_case_obj(&s); } }
        else if(k&&strcmp(k,"negative")==0){ js_match(&s,'['); while(!js_match(&s,']')){ if(js_peek(&s,',')){ s.pos++; continue; } parse_neg_obj(&s); } }
        else { js_skip_value(&s); }
        free(k);
    }
    free(blob);

    int fails=0;

    /* ---- positive cases: decode -> verify -> re-encode == wire ---- */
    for(int i=0;i<g_ncases;i++){
        pcase_t *c=&g_cases[i];
        if(!c->wire){ printf("  [FAIL] %s: no wire bytes\n",c->name); fails++; continue; }

        dnac_fri_wire_package_t *pkg=NULL;
        dnac_fri_codec_status_t cs=dnac_fri_proof_decode(c->wire,c->wire_len,&pkg);
        if(cs!=(dnac_fri_codec_status_t)c->expect_codec || !pkg){
            printf("  [FAIL] %s: decode -> %d (want %d), pkg=%p\n",c->name,(int)cs,c->expect_codec,(void*)pkg);
            fails++; if(pkg)dnac_fri_wire_free(pkg); continue;
        }

        /* verify the decoded structs with a transcript primed from the seed */
        size_t ncom=0;
        const dnac_fri_commitment_with_opening_points_t *com=dnac_fri_wire_commitments(pkg,&ncom);
        dnac_transcript_t *t=dnac_transcript_init(c->seed,c->seed_len);
        if(!t){ printf("  [FAIL] %s: transcript init\n",c->name); fails++; dnac_fri_wire_free(pkg); continue; }
        dnac_fri_status_t fs=dnac_fri_verify(dnac_fri_wire_params(pkg),dnac_fri_wire_proof(pkg),t,com,ncom);
        dnac_transcript_free(t);
        if(fs!=(dnac_fri_status_t)c->expect_fri){
            printf("  [FAIL] %s: dnac_fri_verify -> %d (want %d)\n",c->name,(int)fs,c->expect_fri);
            fails++;
        }

        /* re-encode the decoded structs; must reproduce the original wire exactly */
        uint8_t *re=NULL; size_t rel=0;
        dnac_fri_codec_status_t es=dnac_fri_proof_encode(dnac_fri_wire_params(pkg),dnac_fri_wire_proof(pkg),com,ncom,&re,&rel);
        int rt_ok = (es==DNAC_FRI_CODEC_OK) && (rel==c->wire_len) && (memcmp(re,c->wire,c->wire_len)==0);
        if(!rt_ok){
            printf("  [FAIL] %s: re-encode mismatch (es=%d rel=%zu want_len=%zu memcmp=%d)\n",
                   c->name,(int)es,rel,c->wire_len, re?memcmp(re,c->wire,c->wire_len<rel?c->wire_len:rel):-1);
            fails++;
        }
        free(re);
        dnac_fri_wire_free(pkg);

        /* wrapper: dnac_fri_verify_wire decode+verify+free in one call */
        dnac_fri_status_t wf=(dnac_fri_status_t)-1;
        dnac_transcript_t *t2=dnac_transcript_init(c->seed,c->seed_len);
        dnac_fri_codec_status_t wcs=dnac_fri_verify_wire(c->wire,c->wire_len,t2,&wf);
        dnac_transcript_free(t2);
        int wrap_ok = (wcs==DNAC_FRI_CODEC_OK) && (wf==(dnac_fri_status_t)c->expect_fri);
        if(!wrap_ok){
            printf("  [FAIL] %s: verify_wire -> codec=%d fri=%d (want codec=0 fri=%d)\n",
                   c->name,(int)wcs,(int)wf,c->expect_fri);
            fails++;
        }

        if(rt_ok && wrap_ok && fs==(dnac_fri_status_t)c->expect_fri)
            printf("  [OK ] %-10s decode OK | verify=%d | re-encode==wire (%zu B) | verify_wire OK\n",
                   c->name,(int)fs,c->wire_len);
    }

    /* ---- negative cases: decode must return the specific error, pkg NULL ---- */
    printf("  --- negative malformed cases ---\n");
    for(int i=0;i<g_nnegs;i++){
        pneg_t *c=&g_negs[i];
        if(!c->wire){ printf("  [FAIL] %s: no wire bytes\n",c->name); fails++; continue; }
        dnac_fri_wire_package_t *pkg=NULL;
        dnac_fri_codec_status_t cs=dnac_fri_proof_decode(c->wire,c->wire_len,&pkg);
        int ok = (cs==(dnac_fri_codec_status_t)c->expect_codec) && (pkg==NULL);
        if(!ok){
            printf("  [FAIL] %-22s decode -> %d (want %d), pkg=%p\n",c->name,(int)cs,c->expect_codec,(void*)pkg);
            fails++;
            if(pkg)dnac_fri_wire_free(pkg);
        } else {
            printf("  [OK ] %-22s rejected with code %d, pkg NULL\n",c->name,(int)cs);
        }
    }

    /* ---- misc safety: free(NULL) no-op ---- */
    dnac_fri_wire_free(NULL);

    /* ---- free parsed buffers ---- */
    for(int i=0;i<g_ncases;i++){ free(g_cases[i].wire); free(g_cases[i].seed); }
    for(int i=0;i<g_nnegs;i++){ free(g_negs[i].wire); }

    printf("------------------------------------------------------------\n");
    if(g_ncases<2){ printf("  [FAIL] expected >=2 positive cases, got %d\n",g_ncases); fails++; }
    if(g_nnegs<7){ printf("  [FAIL] expected >=7 negative cases, got %d\n",g_nnegs); fails++; }
    if(fails==0){
        printf("FRI PROOF CODEC GATE: GREEN — %d roundtrips (decode->verify->encode==wire) + %d malformed rejected\n",g_ncases,g_nnegs);
        printf("============================================================\n");
        return 0;
    }
    printf("FRI PROOF CODEC GATE: RED (%d failures)\n",fails);
    return 1;
}
