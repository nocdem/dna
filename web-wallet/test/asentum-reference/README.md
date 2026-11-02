# Optional Asentum SDK fixture oracle

The synthetic test vector in `test/asentum-sign.test.js` was produced with
`@asentum/sdk@0.2.0` and exact dependency lock in
`test/receive-reference/asentum/package-lock.json`. The official SDK tarball's
SHA-512 is `Axwe/di3BRgxp8oj+EqelcZ3xqQWzV00yHi4F/cPjWmL7W4970qFO+o7ODf+S/u5Fk4ZhwcuBvBHWs4ynKgMvA==`.
Run `generate-fixture.mjs` with that lock installed in an isolated temporary
npm project. Its mock chain object does no I/O and the seed is publicly known.
The test uses the full raw transaction hash as a compact byte-equivalence
check and independently verifies its signature with Node/OpenSSL. This is an
SDK interoperability fixture, not proof of consensus acceptance.
