#include "qgp_ckb_sphincs.h"
#include <string.h>
/* Keep all pinned Blake2b exports private to this adapter. */
#define ckb_blake2b_init qgp_ckb_private_ckb_blake2b_init
#define blake2b_init qgp_ckb_private_blake2b_init
#define blake2b_init_key qgp_ckb_private_blake2b_init_key
#define blake2b_init_param qgp_ckb_private_blake2b_init_param
#define blake2b_update qgp_ckb_private_blake2b_update
#define blake2b_final qgp_ckb_private_blake2b_final
#define blake2b qgp_ckb_private_blake2b
#define blake2 qgp_ckb_private_blake2
#define DEFAULT_PERSONAL qgp_ckb_private_DEFAULT_PERSONAL
#include "upstream/blake2b.h"
static const uint8_t message_personal[] = "ckb-sphincs+-msg";
_Static_assert(sizeof(message_personal) - 1 == BLAKE2B_PERSONALBYTES,
               "CKB message personalization must occupy exactly 16 bytes");
static void clear_bytes(void *p,size_t n) {
 volatile uint8_t *v=(volatile uint8_t *)p;
 while(n--) *v++=0;
}
int qgp_ckb_sphincs_param_from_id(uint8_t id) {
 return id>=48 && id<=59 ? (int)id-48 : -1;
}
int qgp_ckb_sphincs_message_hash(uint8_t *digest,size_t dl,const uint8_t *preimage,size_t length) {
 blake2b_param p;
 blake2b_state state;
 uint8_t temporary[32];
 int result;
 static const uint8_t empty=0;
 if(!digest || dl!=32 || (!preimage && length)) return -1;
 memset(&p,0,sizeof(p));
 p.digest_length=32; p.fanout=1; p.depth=1;
 memcpy(p.personal,message_personal,BLAKE2B_PERSONALBYTES);
 result=blake2b_init_param(&state,&p);
 if(!result) result=blake2b_update(&state,preimage?preimage:&empty,length);
 if(!result) result=blake2b_final(&state,temporary,sizeof(temporary));
 if(!result) memcpy(digest,temporary,sizeof(temporary));
 clear_bytes(temporary,sizeof(temporary)); clear_bytes(&state,sizeof(state));
 clear_bytes(&p,sizeof(p)); return result;
}
int qgp_ckb_sphincs_sign_digest(uint8_t id,uint8_t *sig,size_t cap,size_t *len,const uint8_t *digest,size_t dl,const uint8_t *sk,size_t sl,const uint8_t *op,size_t ol) {
 int p=qgp_ckb_sphincs_param_from_id(id);
 if(!len) return -1;
 *len=0;
 if(p<0 || !digest || dl!=32) return -1;
 return qgp_slhdsa_sign(p,sig,cap,len,digest,dl,NULL,0,sk,sl,op,ol);
}
int qgp_ckb_sphincs_verify_digest(uint8_t id,const uint8_t *sig,size_t len,const uint8_t *digest,size_t dl,const uint8_t *pk,size_t pl) {
 int p=qgp_ckb_sphincs_param_from_id(id);
 if(p<0 || !digest || dl!=32) return -1;
 return qgp_slhdsa_verify(p,sig,len,digest,dl,NULL,0,pk,pl);
}
