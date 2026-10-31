// Parent harness for pristine QTC HKDF, HashWriter serialization and P2MR.
// No port sources. GetPQPubKeySize uses the native declaration/size constants;
// this isolated harness does not claim to execute a full wallet or consensus.
#include <pq/pq_keyderivation.h>
#include <script/pqm.h>
#include <hash.h>
#include <array>
#include <cstdio>
#include <cstring>
size_t GetPQPubKeySize(PQAlgorithm a) {return a==PQAlgorithm::ML_DSA_44?MLDSA44_PUBKEY_SIZE:a==PQAlgorithm::SLH_DSA_128S?SLHDSA128S_PUBKEY_SIZE:0;}
int main(int argc,char **argv) {
 if(argc!=2)return 2;
 if(!strcmp(argv[1],"root")) {
  std::vector<unsigned char> ml(MLDSA44_PUBKEY_SIZE),slh(SLHDSA128S_PUBKEY_SIZE);
  if(fread(ml.data(),1,ml.size(),stdin)!=ml.size()||fread(slh.data(),1,slh.size(),stdin)!=slh.size()||fgetc(stdin)!=EOF)return 3;
  auto a=BuildP2MRScript(PQAlgorithm::ML_DSA_44,ml),b=BuildP2MRScript(PQAlgorithm::SLH_DSA_128S,slh);
  auto root=ComputeP2MRBranchHash(ComputeP2MRLeafHash(P2MR_LEAF_VERSION,a),ComputeP2MRLeafHash(P2MR_LEAF_VERSION,b));
  return fwrite(root.begin(),1,32,stdout)==32?0:4;
 }
 std::array<unsigned char,32> master{};
 if(fread(master.data(),1,32,stdin)!=32||fgetc(stdin)!=EOF)return 5;
 const uint32_t coin=!strcmp(argv[1],"testnet")?1:0;
 for(auto algo:{PQAlgorithm::ML_DSA_44,PQAlgorithm::SLH_DSA_128S}) {
  auto seed=pq::DerivePQSeedFromBIP39(master,algo,coin,0,0,0);
  // Exact upstream MakeDeterministicKey HashWriter expression (pqkey.cpp164).
  Span<const unsigned char> material{seed};
  for(uint32_t ctr=0;ctr<4;ctr++) {
   auto block=(HashWriter{}<<material<<ctr).GetSHA256();
   if(fwrite(block.begin(),1,32,stdout)!=32)return 6;
  }
 }
 return 0;
}
