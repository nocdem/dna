// Registration point for the NODUS send module — package (c3) of
// docs/plans/2026-09-25-web-wallet-nodus-send-design.md (C→WASM tier-2 client +
// SPEND builder, not built yet).
//
// `null` = no module: NODUS stays receive-only with no balance (src/nodus/
// network.js NODUS_NETWORK), exactly as before this skeleton. (c3) replaces the
// value with its factory — an async function returning an object that fulfils
// the contract written at the top of src/nodus/client.js.
//
// Deliberately a plain value, not a dynamic import() of a file that does not
// exist yet: Vite/Rollup resolve import() specifiers across the whole module
// graph before dead branches are removed (see the VITE_ENABLE_CPUNK comment in
// src/app.js), so a missing (c3) file would break every build.
export const nodusSendModuleFactory = null;
