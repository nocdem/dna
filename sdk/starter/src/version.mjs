// Point-in-time floor from the Node.js 2026-10-21 security releases.
export const NODE_POLICY = Object.freeze({ checked: '2026-10-24', floors: { 22: [23, 4], 24: [22, 1] } });

export function assertNode(version = process.versions.node) {
  const match = /^v?(\d+)\.(\d+)\.(\d+)$/.exec(version);
  const [major, minor, patch] = match ? match.slice(1).map(Number) : [];
  const floor = NODE_POLICY.floors[major];
  if (!floor || minor < floor[0] || (minor === floor[0] && patch < floor[1])) {
    throw new Error('Use patched Node.js 22.23.4+ (22.x) or 24.22.1+ (24.x). This starter refuses other versions; check newer Node.js security releases too.');
  }
}
