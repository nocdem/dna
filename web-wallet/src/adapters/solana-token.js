// Standard generated Token instructions adapted to the existing web3.js transaction signer.
import { PublicKey, TransactionInstruction } from '@solana/web3.js';
import { findAssociatedTokenPda, TOKEN_PROGRAM_ADDRESS, getCreateAssociatedTokenIdempotentInstruction, getTransferCheckedInstruction } from '@solana-program/token';
export const TOKEN_PROGRAM_ID = new PublicKey(TOKEN_PROGRAM_ADDRESS);
function legacyInstruction(instruction) {
  return new TransactionInstruction({ programId: new PublicKey(instruction.programAddress), data: Buffer.from(instruction.data), keys: instruction.accounts.map(account => ({ pubkey: new PublicKey(account.address), isSigner: !!(account.role & 2), isWritable: !!(account.role & 1) })) });
}
export async function getAssociatedTokenAddress(mint, owner) {
  if (!PublicKey.isOnCurve(owner.toBytes())) throw new Error('Recipient must be an on-curve Solana wallet address.');
  const [address] = await findAssociatedTokenPda({ mint: mint.toBase58(), owner: owner.toBase58(), tokenProgram: TOKEN_PROGRAM_ADDRESS });
  return new PublicKey(address);
}
export function createAssociatedTokenAccountIdempotentInstruction(payer, ata, owner, mint) {
  return legacyInstruction(getCreateAssociatedTokenIdempotentInstruction({ payer: { address: payer.toBase58(), role: 3 }, ata: ata.toBase58(), owner: owner.toBase58(), mint: mint.toBase58() }));
}
export function createTransferCheckedInstruction(source, mint, destination, owner, amount, decimals) {
  return legacyInstruction(getTransferCheckedInstruction({ source: source.toBase58(), mint: mint.toBase58(), destination: destination.toBase58(), authority: { address: owner.toBase58(), role: 2 }, amount, decimals }));
}
