/* Synthetic offline fixture producer for independently verifying the bridge. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
uint8_t *mldsa65_seed(void), *mldsa65_message(void), *mldsa65_public_key(void), *mldsa65_signature(void);
int mldsa65_sign(int,int); void mldsa65_clear(void);
int main(int argc,char **argv) {
    if (argc != 2) return 1;
    int ctx=atoi(argv[1]);
    for(int i=0;i<32;i++) mldsa65_seed()[i]=(uint8_t)i;
    memcpy(mldsa65_message(),"test message",12);
    if(mldsa65_sign(12,ctx)) return 2;
    for (int i=0;i<32;i++) if (mldsa65_seed()[i]) return 4;
    for (int i=0;i<12;i++) if (mldsa65_message()[i]) return 5;
    if(fwrite(mldsa65_public_key(),1,1952,stdout)!=1952 || fwrite(mldsa65_signature(),1,3309,stdout)!=3309) return 3;
    mldsa65_clear();return 0;
}
