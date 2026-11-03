#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "sign.h"
static int readfile(const char*p,uint8_t*b,size_t n){FILE*f=fopen(p,"rb");if(!f)return -1;size_t x=fread(b,1,n,f);fclose(f);return x==n?0:-1;}
int main(int argc,char **argv){uint8_t pk[1312],sig[2420],msg[32];if(argc!=4||readfile(argv[1],pk,sizeof pk)||readfile(argv[2],sig,sizeof sig)||readfile(argv[3],msg,sizeof msg))return 2;return crypto_sign_verify(sig,sizeof sig,msg,sizeof msg,NULL,0,pk)?1:0;}
