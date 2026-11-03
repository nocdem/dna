#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#define WITNESS_ARGS_LAZY_VALIDATOR_H_
#define CKB_SUCCESS 0
#define CKB_INDEX_OUT_OF_BOUND 1
#define CKB_SOURCE_INPUT 1
#define CKB_SOURCE_GROUP_INPUT 2
#define MOL2_DATA_SOURCE_LEN(n) (n)
#define ASSERT(x) do {if(!(x)) abort();}while(0)
typedef struct {uint32_t size;} mol2_cursor_t;
typedef struct {mol2_cursor_t cur;} opt;
typedef struct witness WitnessArgsType;
typedef struct {opt (*input_type)(WitnessArgsType*);opt (*output_type)(WitnessArgsType*);} methods;
struct witness {methods *t;};
static uint32_t mol2_read_at(mol2_cursor_t *c,uint8_t*b,uint32_t n){(void)c;(void)b;(void)n;return 0;}
static void mol2_advance(mol2_cursor_t*c,uint32_t n){(void)c;(void)n;}
static int mol2_lazy_witness_args_load(uint8_t*b,uint32_t n,size_t i,size_t s,int v,WitnessArgsType*w){(void)b;(void)n;(void)i;(void)s;(void)v;(void)w;return -1;}
static uint8_t hashbuf[32],cell[65536];static size_t celllen;
static int load_bytes(const uint8_t *src,size_t sz,void *out,uint64_t *len,size_t offset){if(offset>sz)return 1;size_t rem=sz-offset,n=*len<rem?*len:rem;memcpy(out,src+offset,n);*len=rem;return 0;}
static int ckb_load_tx_hash(void*out,uint64_t*len,size_t offset){return load_bytes(hashbuf,32,out,len,offset);}
static int ckb_load_cell(void*out,uint64_t*len,size_t offset,size_t index,size_t source){if(index||source!=CKB_SOURCE_INPUT)return 1;return load_bytes(cell,celllen,out,len,offset);}
static int ckb_load_cell_data(void*out,uint64_t*len,size_t offset,size_t index,size_t source){if(index||source!=CKB_SOURCE_INPUT)return 1;return load_bytes((uint8_t*)"",0,out,len,offset);}
static int ckb_load_witness(void*out,uint64_t*len,size_t offset,size_t index,size_t source){(void)out;(void)len;(void)offset;(void)index;(void)source;return 1;}
#include "ckb_tx_message_all.h"
static opt none(WitnessArgsType*w){(void)w;opt o={{0}};return o;}
static int writer(const uint8_t*b,size_t n,void*c){return fwrite(b,1,n,(FILE*)c)==n?0:1;}
int main(int argc,char**argv){if(argc!=3)return 2;FILE*f=fopen(argv[1],"rb");if(!f||fread(hashbuf,1,32,f)!=32)return 3;fclose(f);f=fopen(argv[2],"rb");if(!f)return 4;celllen=fread(cell,1,sizeof cell,f);fclose(f);methods m={none,none};WitnessArgsType w={&m};return ckb_tx_message_all_generate_with_witness_args(writer,stdout,&w);}
