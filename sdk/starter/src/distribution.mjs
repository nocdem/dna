// An explicit release allowlist. Adding a dependency requires reviewing this
// closure and the package smoke test. No recursive copy of a working tree.
export const COMPILER_ARCHIVE = 'nodus-solc-0.8.30-nodus.addr256-linux-x86_64';
export const COMPILER_SHA256 = 'a09d6486c944a795009f08dbc8210ce2eee2785248f9f5f7edc2aaa9c6934649';
export const COMPILER_VERSION = 'Version: 0.8.30+nodus.addr256.commit.73712a01.Linux.g++';
export const COMPILER_FILES = ['solc-nodus', 'README.md', 'NOTICE', 'LICENSE.txt', 'LICENSES-solc.txt'];
export const CONTRACT_SOURCES = [
  'access/AccessControl.sol', 'access/Ownable.sol', 'crypto/MLDSA87.sol', 'crypto/MLDSA87Attested.sol',
  'governance/Timelock.sol', 'payments/MilestoneEscrow.sol', 'security/Pausable.sol',
  'security/ReentrancyGuard.sol', 'vaults/MultisigVault.sol'
];
export const STARTER_FILES = [
  '.gitignore', '.npmrc', '.nvmrc', 'package.json', 'package-lock.json', 'README.md', 'starter.config.example.json',
  'bin/nodus-starter.mjs', 'scripts/build.mjs',
  'src/version.mjs', 'src/config.mjs', 'src/journal.mjs', 'src/session.mjs', 'src/distribution.mjs',
  'src/artifacts.mjs', 'src/sdk.mjs', 'src/commands.mjs', 'src/compile.mjs',
  'templates/manifest.json',
  'test/policy.test.mjs', 'test/journal.test.mjs', 'test/session.test.mjs', 'test/artifacts.test.mjs', 'test/commands.test.mjs', 'test/package.smoke.mjs'
];
const SDK_FILES = ['package.json', 'src/index.js', 'src/sdk.js', 'src/identity.js', 'src/network.js', 'src/review.js', 'src/wallet.js', 'wasm/send-node.mjs', 'wasm/send-node.wasm'];
const WALLET_FILES = [
  'core.js', 'rpc-transport.js', 'recovery.js', 'adapters/nodus.js',
  'evm/abi.js', 'evm/address.js', 'evm/contract.js', 'evm/rpc.js', 'evm/units.js',
  'nodus/client.js', 'nodus/derive.js', 'nodus/history.js', 'nodus/names.js', 'nodus/network.js',
  'nodus/send-module.js', 'nodus/mldsa87.wasm'
];
const LICENSE_FILES = ['musl-COPYRIGHT.txt', 'json-c-0.17-COPYING.txt', 'OpenSSL-3.0.15-LICENSE.txt', 'Emscripten-LICENSE.txt'];

// [source relative to repo root, destination relative to archive root].
export const COPY_FILES = [
  ...STARTER_FILES.map(path => [`sdk/starter/${path}`, path]),
  ...SDK_FILES.map(path => [`sdk/js/${path}`, `runtime/sdk/js/${path}`]),
  ...WALLET_FILES.map(path => [`web-wallet/src/${path}`, `runtime/web-wallet/src/${path}`]),
  ...CONTRACT_SOURCES.map(path => [`nodus/tools/evm/contracts/src/${path}`, `templates/library/src/${path}`]),
  ...['VERSION', 'README.md', 'out/VERSION.txt'].map(path => [`nodus/tools/evm/contracts/${path}`, `templates/library/${path}`]),
  ...['MultisigVault', 'MilestoneEscrow'].flatMap(name => [
    [`nodus/tools/evm/contracts/out/${name}.abi.json`, `templates/library/out/${name}.abi.json`],
    ...['creation', 'runtime'].map(kind => [`nodus/tools/evm/contracts/out/default/${name}.${kind}.hex`, `templates/library/out/default/${name}.${kind}.hex`])
  ]),
  ...['0001-nodus-address-256.patch', 'build.sh', 'README.md'].map(path => [`nodus/tools/evm/solc/${path}`, `compiler/source/${path}`]),
  ...LICENSE_FILES.map(path => [`web-wallet/licenses/${path}`, `licenses/wasm/${path}`]),
  ['shared/crypto/enc/kem/LICENSE-upstream-pq-crystals', 'licenses/wasm/LICENSE-upstream-pq-crystals'],
  ['LICENSE', 'LICENSE']
];
export const DISTRIBUTION_FILES = [...COPY_FILES.map(([, dest]) => dest), ...COMPILER_FILES.map(path => `compiler/${path}`)].sort();
export const PROTECTED_DIRECTORIES = ['bin', 'src', 'scripts', 'test', 'runtime', 'templates', 'compiler', 'licenses'];

export function assertDistributionPaths(paths) {
  const actual = [...paths].sort();
  if (actual.length !== DISTRIBUTION_FILES.length || actual.some((path, i) => path !== DISTRIBUTION_FILES[i])) {
    throw new Error('Distribution file list differs from the release allowlist (missing or unexpected artifact).');
  }
}
