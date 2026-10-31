// Parent oracle: execute pinned native encoder/decoder, never wallet JS.
#include "pubkey.h"
#include "utiladdress.h"
#include <iostream>
#include <iterator>
#include <vector>
int main() {
  std::vector<unsigned char> raw{std::istreambuf_iterator<char>(std::cin), {}};
  if (raw.size() != CPubKey::SIZE) return 2;
  CPubKey pk(raw); if (!pk.IsValid()) return 3;
  const auto address = EncodeDilithiumAddress(pk, "sq");
  const auto dest = DecodeDestination(address, "sq");
  if (dest.which() != 3 || !IsValidDestinationString(address, "sq")) return 4;
  if (IsValidDestinationString("2w3ohH4opzABfoHRsdNJwCW6cPwHxWkAa3ok", "sq")) return 5;
  const auto* witness = boost::get<WitnessV1ScriptHash>(&dest);
  uint256 expected; CSHA256().Write(raw.data(), raw.size()).Finalize(expected.begin());
  if (!witness || *witness != expected) return 6;
  std::cout << address;
}
