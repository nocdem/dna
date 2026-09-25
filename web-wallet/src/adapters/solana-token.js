// Standard generated Token instructions, consumed as @solana/kit instructions.
import { AccountRole, getAddressEncoder } from '@solana/kit';
import { ed25519 } from '@noble/curves/ed25519';
import { findAssociatedTokenPda, TOKEN_PROGRAM_ADDRESS, getCreateAssociatedTokenIdempotentInstruction, getTransferCheckedInstruction } from '@solana-program/token';
export const TOKEN_PROGRAM_ID = TOKEN_PROGRAM_ADDRESS;
// The same on-curve test the wallet used through @solana/web3.js 1.99.0
// (PublicKey.isOnCurve = ed25519.ExtendedPoint.fromHex on the 32 address bytes).
function isOnCurve(owner) {
  try { ed25519.ExtendedPoint.fromHex(getAddressEncoder().encode(owner)); return true; } catch { return false; }
}
export async function getAssociatedTokenAddress(mint, owner) {
  if (!isOnCurve(owner)) throw new Error('Recipient must be an on-curve Solana wallet address.');
  const [address] = await findAssociatedTokenPda({ mint, owner, tokenProgram: TOKEN_PROGRAM_ADDRESS });
  return address;
}
export function createAssociatedTokenAccountIdempotentInstruction(payer, ata, owner, mint) {
  return getCreateAssociatedTokenIdempotentInstruction({ payer: { address: payer, role: AccountRole.WRITABLE_SIGNER }, ata, owner, mint });
}
export function createTransferCheckedInstruction(source, mint, destination, owner, amount, decimals) {
  return getTransferCheckedInstruction({ source, mint, destination, authority: { address: owner, role: AccountRole.READONLY_SIGNER }, amount, decimals });
}
