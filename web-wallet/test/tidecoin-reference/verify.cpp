// Synthetic-only independent consensus script oracle. Built against the
// pinned Tidecoin core libraries, not the wallet's WASM implementation.
#include <iostream>
#include <string>
#include <vector>
#include <stdexcept>
#include <streams.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <consensus/tx_check.h>
#include <consensus/validation.h>
#include <policy/policy.h>
#include <policy/feerate.h>
#include <util/translation.h>
const TranslateFn G_TRANSLATION_FUN{nullptr};
static std::vector<unsigned char> hex(const std::string& s){if(s.size()%2)throw std::runtime_error("odd hex");std::vector<unsigned char> out;for(size_t i=0;i<s.size();i+=2){auto n=[](char c)->int{if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;throw std::runtime_error("bad hex");};out.push_back((n(s[i])<<4)|n(s[i+1]));}return out;}
int main(int argc,char**argv){try{if(argc!=4)return 2;auto raw=hex(argv[1]),prev=hex(argv[2]);DataStream stream{raw};CTransaction tx(deserialize,TX_WITH_WITNESS,stream);if(!stream.empty()||tx.vin.size()!=1)return 3;TxValidationState state;if(!CheckTransaction(tx,state)){std::cerr<<"invalid transaction: "<<state.ToString()<<"\n";return 4;}std::string reason;if(!IsStandardTx(tx,std::nullopt,true,CFeeRate(DUST_RELAY_TX_FEE),reason)){std::cerr<<"nonstandard="<<reason<<"\n";return 5;}CScript pub(prev.begin(),prev.end());ScriptError error;const std::string mode=argv[3];if(mode!="legacy"&&mode!="strict"&&mode!="standard"&&mode!="strict-standard")return 2;const bool legacy=mode=="legacy"||mode=="standard";const bool standard=mode=="standard"||mode=="strict-standard";const unsigned flags=(standard?STANDARD_SCRIPT_VERIFY_FLAGS:(SCRIPT_VERIFY_P2SH|SCRIPT_VERIFY_WITNESS))|(legacy?0:SCRIPT_VERIFY_PQ_STRICT);TransactionSignatureChecker checker(&tx,0,123457000,MissingDataBehavior::FAIL,legacy);const bool ok=VerifyScript(tx.vin[0].scriptSig,pub,&tx.vin[0].scriptWitness,flags,checker,&error);std::cout<<(ok?"accepted":"rejected")<<" script_error="<<int(error)<<" dust="<<GetDustThreshold(tx.vout[0],CFeeRate(DUST_RELAY_TX_FEE))<<'\n';return ok?0:1;}catch(const std::exception&e){std::cerr<<e.what()<<'\n';return 2;}}
