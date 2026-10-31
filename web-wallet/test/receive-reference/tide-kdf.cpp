// Parent harness: invokes pristine Tidecoin PQHD; stdin root32, stdout stream64.
#include <pq/pqhd_kdf.h>
#include <cstdio>
int main() {
 std::array<uint8_t,32> seed{};
 if(fread(seed.data(),1,32,stdin)!=32 || fgetc(stdin)!=EOF) return 2;
 std::array<uint32_t,6> path{10007,6868,7,0,0,0};for(auto &i:path)i|=0x80000000U;
 auto leaf=pqhd::DerivePath(pqhd::MakeMasterNode(seed),path);if(!leaf)return 3;
 auto stream=pqhd::DeriveKeygenStreamKey(leaf->node_secret,path);if(!stream)return 4;
 auto block=pqhd::DeriveKeygenStreamBlock(stream->Span(),0);
 return fwrite(block.data(),1,block.size(),stdout)==block.size()?0:5;
}
