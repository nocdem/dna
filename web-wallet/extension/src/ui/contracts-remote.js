import { EvmAccount as PublicAccount, Contract as PublicContract } from '../../../src/evm/contract.js';
import { Interface as PublicInterface } from '../../../src/evm/abi.js';
import { formatRaw, formatWei } from '../../../src/evm/units.js';

// The page retains only ABI, public values and review ids. Signing/building
// and the account's one-pending queue stay on s.contractAccount in nodus.js.
export class Interface extends PublicInterface { constructor(abi) { super(abi); this.source = abi; } }
export const jsonValues = value => JSON.parse(JSON.stringify(value, (_key, item) => typeof item === 'bigint' ? item.toString() : item instanceof Uint8Array ? [...item] : item));
export class EvmAccount {
  constructor({ client, fingerprint }) {
    this.client = client; this.fingerprint = fingerprint; this.pending = false;
    // Address formatting only, using the web wallet's existing implementation.
    this.displayAddress = new PublicAccount({ client, fingerprint }).displayAddress;
  }
  waiting() { return this.pending; }
  async account() { const value = await this.client.request('contractAccount', [{}]); this.pending = value.pending; return value; }
  simulate(args) { return this.client.request('contractSimulate', [jsonValues(args)]); }
  estimate(args) { return this.client.request('contractEstimate', [jsonValues(args)]); }
  ticket(ticketId) { return this.client.request('contractTicket', [{ ticketId }]); }
  deposit(amount) { return this.prepare({ action: 'deposit', amount: formatRaw(amount) }); }
  withdraw(amount, dest) { return this.prepare({ action: 'withdraw', amount: formatRaw(amount), dest }); }
  redeem(ticketId, dest) { return this.prepare({ action: 'redeem', ticketId, dest }); }
  async prepare(fields) {
    const value = await this.client.request('prepareNodusContract', [jsonValues(fields)]);
    const decoded = { ...value.decoded };
    for (const key of ['amount', 'fee', 'valueWei']) decoded[key] = BigInt(decoded[key]);
    let consumed = false;
    return { ...value, decoded,
      cancel: () => { if (!consumed) { consumed = true; void this.client.request('cancelNodusSend', [value.id]).catch(() => {}); } },
      confirm: async () => {
        consumed = true;
        try {
          const intentId = await this.client.request('confirmNodusSend', [value.id]); this.pending = true;
          const receipt = this.client.request('getNodusContractReceipt', [intentId]).finally(() => { this.pending = false; });
          return { intentId, receipt };
        } catch (error) {
          if (error.data?.activityTracked) {
            const receipt = this.client.request('getNodusContractReceipt', [value.intentId]);
            error.sent = { intentId: value.intentId, receipt };
          }
          throw error;
        }
      } };
  }
}
export class Contract extends PublicContract {
  constructor(options) { super(options); this.sourceAbi = options.abi instanceof Interface ? options.abi.source : options.abi; }
  prepareSend(fn, args = [], { valueWei = 0n } = {}) {
    return this.account.prepare({ action: 'call', address: this.address, abi: this.sourceAbi,
      fn: this.iface.getFunction(fn).signature, args: jsonValues(args), value: formatWei(valueWei) });
  }
  static prepareDeploy({ account, bytecode, abi, args = [], valueWei = 0n }) {
    return account.prepare({ action: 'deploy', bytecode, abi: abi instanceof Interface ? abi.source : abi, args: jsonValues(args), value: formatWei(valueWei) });
  }
}
