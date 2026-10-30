/* Invalid caller arguments must fail before consuming keys/entropy or writing
 * outputs. These cases obey C pointer validity; they do not dereference forged
 * pointers or claim to validate a caller's inaccessible memory. */
#include "vector_io.h"
#include "qgp_algorand_falcon.h"
#include "qgp_tidecoin_falcon.h"
#include "qgp_slhdsa.h"
#include "qgp_ckb_sphincs.h"
#include "qgp_mldsa.h"
unsigned long test_boundaries(void) {
    unsigned long before=checks;uint8_t out[8192],pk[3000],sk[6000],seed[96]={0},ctx[256]={0};size_t n=99;
    memset(out,0xA5,sizeof out);memset(pk,0xA5,sizeof pk);memset(sk,0xA5,sizeof sk);
    CHECK(qgp_algorand_falcon_keypair_from_seed(pk,1793,sk,2305,NULL,1)!=0);
    CHECK(qgp_algorand_falcon_keypair_from_seed(pk,1792,sk,2305,seed,32)!=0);
    CHECK(qgp_algorand_falcon_sign(out,1423,&n,NULL,1,sk,2305)!=0&&n==0);
    CHECK(qgp_algorand_falcon_sign(out,1423,NULL,NULL,0,sk,2305)!=0);
    CHECK(qgp_algorand_falcon_to_ct(out,1537,pk,2)!=0);
    CHECK(qgp_algorand_falcon_to_ct(out,1538,NULL,2)!=0);
    CHECK(qgp_algorand_falcon_verify_ct(NULL,1538,NULL,0,pk,1793)!=0);
    CHECK(qgp_tidecoin_falcon_keypair_from_seed(pk,897,sk,1281,NULL,48)!=0);
    CHECK(qgp_tidecoin_falcon_keypair_from_seed(pk,896,sk,1281,seed,48)!=0);
    CHECK(qgp_tidecoin_falcon_sign(out,688,&n,NULL,0,sk,1281,NULL,NULL)!=0&&n==0);
    CHECK(qgp_tidecoin_falcon_sign(out,688,NULL,NULL,0,sk,1281,NULL,NULL)!=0);
    CHECK(qgp_tidecoin_falcon_verify(out,1,NULL,1,pk,897)!=0);
    for(int p=44;p<=65;p+=21) {
        qgp_mldsa_params s;CHECK(qgp_mldsa_get_params(p,&s)==0);
        CHECK(qgp_mldsa_get_params(p,NULL)!=0);
        CHECK(qgp_mldsa_keypair_from_seed(p,pk,s.public_key_bytes,sk,s.secret_key_bytes,seed,31)!=0);
        CHECK(qgp_mldsa_keypair_from_seed(p,NULL,s.public_key_bytes,sk,s.secret_key_bytes,seed,32)!=0);
        CHECK(qgp_mldsa_sign(p,out,sizeof out,&n,seed,1,ctx,256,sk,s.secret_key_bytes,seed,32)!=0&&n==0);
        CHECK(qgp_mldsa_sign(p,out,sizeof out,&n,seed,1,NULL,1,sk,s.secret_key_bytes,seed,32)!=0&&n==0);
        CHECK(qgp_mldsa_sign_internal(p,out,sizeof out,&n,NULL,1,sk,s.secret_key_bytes,seed,32)!=0&&n==0);
        CHECK(qgp_mldsa_sign_internal(p,out,sizeof out,NULL,seed,1,sk,s.secret_key_bytes,seed,32)!=0);
        CHECK(qgp_mldsa_verify(p,out,s.signature_bytes,seed,1,ctx,256,pk,s.public_key_bytes)!=0);
        CHECK(qgp_mldsa_verify_internal(p,NULL,s.signature_bytes,seed,1,pk,s.public_key_bytes)!=0);
    }
    for(int p=0;p<12;p++) {
        qgp_slhdsa_params s;CHECK(qgp_slhdsa_get_params(p,&s)==0);
        CHECK(qgp_slhdsa_keypair_from_seed(p,pk,s.public_key_bytes,sk,s.secret_key_bytes,seed,s.seed_bytes-1)!=0);
        CHECK(qgp_slhdsa_keypair_from_seed(p,pk,s.public_key_bytes,NULL,s.secret_key_bytes,seed,s.seed_bytes)!=0);
        CHECK(qgp_slhdsa_sign(p,out,0,&n,seed,SIZE_MAX,ctx,0,sk,s.secret_key_bytes,seed,s.optrand_bytes)!=0&&n==0);
        CHECK(qgp_slhdsa_sign(p,out,0,&n,seed,SIZE_MAX-1,ctx,1,sk,s.secret_key_bytes,seed,s.optrand_bytes)!=0&&n==0);
        CHECK(qgp_slhdsa_sign(p,out,0,&n,seed,1,ctx,256,sk,s.secret_key_bytes,seed,s.optrand_bytes)!=0&&n==0);
        CHECK(qgp_slhdsa_sign(p,out,0,&n,seed,1,NULL,1,sk,s.secret_key_bytes,seed,s.optrand_bytes)!=0&&n==0);
        CHECK(qgp_slhdsa_sign_internal(p,out,0,&n,seed,1,sk,s.secret_key_bytes,seed,s.optrand_bytes)!=0&&n==0);
        CHECK(qgp_slhdsa_sign_internal(p,out,0,NULL,seed,1,sk,s.secret_key_bytes,seed,s.optrand_bytes)!=0);
        CHECK(qgp_slhdsa_verify(p,out,0,seed,SIZE_MAX,ctx,0,pk,s.public_key_bytes)!=0);
        CHECK(qgp_slhdsa_verify(p,out,0,seed,1,ctx,SIZE_MAX,pk,s.public_key_bytes)!=0);
        CHECK(qgp_slhdsa_verify_internal(p,NULL,s.signature_bytes,seed,1,pk,s.public_key_bytes)!=0);
    }
    qgp_mldsa_params m;CHECK(qgp_mldsa_get_params(-1,&m)!=0&&qgp_mldsa_get_params(87,&m)!=0);
    CHECK(qgp_ckb_sphincs_sign_digest(47,out,0,&n,seed,32,sk,64,seed,16)!=0&&n==0);
    CHECK(qgp_ckb_sphincs_sign_digest(48,out,0,&n,seed,31,sk,64,seed,16)!=0&&n==0);
    CHECK(qgp_ckb_sphincs_message_hash(out,31,seed,32)!=0);
    CHECK(qgp_ckb_sphincs_message_hash(out,32,NULL,1)!=0);
    CHECK(qgp_ckb_sphincs_verify_digest(60,out,0,seed,32,pk,32)!=0);
    for(size_t i=0;i<sizeof out;i++)CHECK(out[i]==0xA5);
    for(size_t i=0;i<sizeof pk;i++)CHECK(pk[i]==0xA5);
    for(size_t i=0;i<sizeof sk;i++)CHECK(sk[i]==0xA5);
    return checks-before;
}
