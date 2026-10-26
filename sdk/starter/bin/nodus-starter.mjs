#!/usr/bin/env node
import { assertNode } from '../src/version.mjs';

// This gate deliberately runs before importing SDK/crypto, reading a phrase,
// executing the compiler or opening sockets. There is no override environment.
let phrase;
try {
  assertNode();
  const { HELP, prepareCommand, executeCommand } = await import('../src/commands.mjs');
  const args = process.argv.slice(2);
  if (!args.length || (args.length === 1 && ['help', '--help', '-h'].includes(args[0]))) {
    console.log(HELP);
  } else {
    const { doctor } = await import('../src/artifacts.mjs');
    const manifest = await doctor();
    const { loadSdk, loadTemplates } = await import('../src/sdk.mjs');
    let sdk;
    try { sdk = await loadSdk(); } catch { throw new Error('Cannot import the packaged SDK. Run npm ci --ignore-scripts from the extracted package root.'); }
    const { readConfig, configBase } = await import('../src/config.mjs');
    const emit = value => console.log(JSON.stringify(value, (_, item) => typeof item === 'bigint' ? item.toString() : item, 2));
    if (args[0] === 'doctor') {
      if (args.length !== 1) throw new Error('doctor takes no arguments.');
      const templates = await loadTemplates();
      for (const template of Object.values(templates)) new sdk.Interface(template.abi);
      emit({ ok: true, node: process.versions.node, sourceCommit: manifest.sourceCommit, worktreeDirty: manifest.worktreeDirty,
        filesChecked: Object.keys(manifest.files).length, templates: Object.keys(templates), network: sdk.DEFAULT_NETWORK.chainId,
        note: 'Offline integrity/import/compiler check. No chain connection, transaction or external audit.' });
    } else if (args[0] === 'compile') {
      if (args.length !== 2) throw new Error('compile needs vault or escrow.');
      const { compileTemplate } = await import('../src/compile.mjs');
      emit(await compileTemplate(args[1]));
    } else {
      let config, command;
      if (args[0] === 'identity') {
        if (args.length !== 1) throw new Error('identity takes no arguments.');
      } else {
        const source = await readConfig(process.env.NODUS_CONFIG || 'starter.config.json');
        config = configBase(source, sdk);
        command = prepareCommand(args, source, sdk);
        if (command.write && (!process.stdin.isTTY || !process.stdout.isTTY)) throw new Error('Every write needs an interactive terminal for review and confirmation. Nothing was built or sent.');
      }
      phrase = process.env.NODUS_PHRASE?.trim().replace(/\s+/g, ' ');
      delete process.env.NODUS_PHRASE;
      if (!phrase) throw new Error('Set NODUS_PHRASE in the environment using a dedicated testnet identity; never pass it as an argument or put it in config.');
      if (args[0] === 'identity') {
        emit(await sdk.deriveIdentity(phrase));
      } else {
        const { withAccount } = await import('../src/session.mjs');
        const { homedir } = await import('node:os');
        const { join } = await import('node:path');
        const { createInterface } = await import('node:readline/promises');
        const stateDir = process.env.NODUS_STATE_DIR || join(process.env.XDG_STATE_HOME || join(homedir(), '.local/state'), 'nodus-starter');
        const templates = await loadTemplates();
        const confirm = async review => {
          if (!process.stdin.isTTY || !process.stdout.isTTY) return false;
          console.log('\nReview (already signed locally; nothing broadcast yet)');
          for (const [label, value] of review.rows) console.log(`${label}: ${value}`);
          console.log(`Intent: ${review.intentId}\nOnly yes broadcasts. The SDK review expires after 60 seconds.`);
          const terminal = createInterface({ input: process.stdin, output: process.stdout });
          try { return (await terminal.question('Type yes to broadcast: ')).trim() === 'yes'; } finally { terminal.close(); }
        };
        const result = await withAccount({ sdk, phrase, config, stateDir, write: command.write, confirm,
          run: (evm, options) => executeCommand(command, { evm, options, templates, sdk, emit }) });
        emit(result);
        if (command.write && result.status !== 'applied-success') process.exitCode = 1;
        if (command.action === 'deploy' && result.status === 'applied-success' && !result.address) {
          console.error('Deployment receipt address did not match the signed expectation. Inspect the transaction; do not deploy a replacement automatically.');
          process.exitCode = 1;
        }
      }
    }
  }
} catch (error) {
  let message = String(error?.message || 'Starter failed.');
  for (const secret of [phrase, process.env.NODUS_PHRASE].filter(Boolean)) message = message.split(secret).join('[redacted]');
  console.error(message.replace(/[\u0000-\u0008\u000b-\u001f\u007f]/g, ''));
  process.exitCode = 1;
} finally {
  phrase = undefined;
}
