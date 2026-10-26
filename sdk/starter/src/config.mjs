import { readFile } from 'node:fs/promises';

export function integer(value, label, { positive = false, bits = 256 } = {}) {
  if (typeof value !== 'string' || !/^(0|[1-9]\d{0,77})$/.test(value)) throw new Error(`${label} must be a decimal integer string.`);
  const result = BigInt(value);
  if (result < (positive ? 1n : 0n) || result >= 2n ** BigInt(bits)) throw new Error(`${label} is outside its unsigned ${bits}-bit range${positive ? ' (must be positive)' : ''}.`);
  return result;
}

function fields(object, allowed, label) {
  if (!object || typeof object !== 'object' || Array.isArray(object)) throw new Error(`${label} must be an object.`);
  if (Object.keys(object).some(key => !allowed.includes(key))) throw new Error(`Unsupported ${label} field; recovery phrases and keys belong only in the environment.`);
}

export async function readConfig(path) {
  let bytes;
  try { bytes = await readFile(path); } catch { throw new Error(`Cannot read config ${path}; copy starter.config.example.json to starter.config.json and fill the required fields.`); }
  if (bytes.length > 65536) throw new Error('Config is too large.');
  try { return JSON.parse(bytes.toString('utf8')); } catch { throw new Error('Config is not valid JSON.'); }
}

export function configBase(config, sdk) {
  fields(config, ['version', 'endpoint', 'network', 'evm', 'maxFeeRaw', 'vault', 'escrow'], 'config');
  if (config.version !== 1) throw new Error('Config version must be 1.');
  if (config.vault !== undefined) fields(config.vault, ['address', 'owners', 'threshold'], 'vault config');
  if (config.escrow !== undefined) fields(config.escrow, ['address', 'payer', 'payee', 'arbiter', 'amountsWei', 'deadline'], 'escrow config');
  return {
    network: sdk.resolveNetwork({ network: config.network, endpoint: config.endpoint }),
    evm: sdk.resolveEvmNetwork(config.evm),
    maxFee: integer(config.maxFeeRaw, 'maxFeeRaw', { positive: true, bits: 64 })
  };
}

function nonzero(value, sdk) {
  const parsed = sdk.parseAddress(value);
  if (/^0{64}$/.test(parsed)) throw new Error('A nonzero 32-byte address is required.');
  return `0x${parsed}`;
}

export function contractAddress(config, kind, sdk) {
  return nonzero(config[kind]?.address, sdk);
}

export function vaultArgs(config, sdk) {
  const v = config.vault;
  if (!Array.isArray(v?.owners) || v.owners.length < 1 || v.owners.length > 32) throw new Error('vault.owners needs 1 to 32 distinct addresses.');
  const owners = v.owners.map(value => nonzero(value, sdk));
  if (new Set(owners).size !== owners.length) throw new Error('vault.owners must be distinct.');
  const threshold = integer(v.threshold, 'vault.threshold', { positive: true });
  if (threshold > BigInt(owners.length)) throw new Error('vault.threshold exceeds the number of owners.');
  return [owners, threshold];
}

export function escrowArgs(config, sdk) {
  const e = config.escrow;
  if (!e) throw new Error('escrow config is required.');
  const parties = [e.payer, e.payee, e.arbiter].map(value => nonzero(value, sdk));
  if (new Set(parties).size !== 3) throw new Error('The escrow parties must be distinct.');
  if (!Array.isArray(e.amountsWei) || e.amountsWei.length < 1 || e.amountsWei.length > 32) throw new Error('escrow.amountsWei needs 1 to 32 milestones.');
  const amounts = e.amountsWei.map(value => integer(value, 'escrow amount', { positive: true }));
  if (amounts.some(value => value % 10000000000n !== 0n)) throw new Error('Each escrow amount must be a multiple of 10000000000 wei (one raw NODUS unit).');
  if (amounts.reduce((a, b) => a + b, 0n) >= 2n ** 256n) throw new Error('The escrow total overflows uint256.');
  return [...parties, amounts, integer(e.deadline, 'escrow.deadline', { positive: true })];
}
