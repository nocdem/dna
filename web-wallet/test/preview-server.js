// One `vite preview` per browser test, started and stopped here.
//
// Why (2026-10-02): `vite preview … --strictPort` exits when its port is
// taken, but the tests only polled the URL, so a server left over from an
// earlier run (an orphan of a test process that had exited) answered
// instead and the test checked THAT build. Two such orphans, started from
// /opt/dna/web-wallet on 2026-09-30 and 2026-10-01, made test:browser and
// test:security check an old dist for days. Leftovers were found again
// after a normal run (orphans with ppid 1 although the tests call kill() in
// `finally`), so:
//   - a port that already answers is refused before anything is started;
//   - the server must answer while it is still running (an exit fails);
//   - stop() kills with SIGKILL, and the process exit hook kills it too.
import { spawn } from 'node:child_process';
import net from 'node:net';
import { setTimeout as delay } from 'node:timers/promises';

function portAnswers(port) {
  return new Promise(resolve => {
    const socket = net.connect({ host: '127.0.0.1', port });
    socket.once('connect', () => { socket.destroy(); resolve(true); });
    socket.once('error', () => resolve(false));
  });
}

// `args`: arguments after the node executable (the vite script first).
export async function startPreview(args, port, options = {}) {
  if (await portAnswers(port)) throw new Error(`Port ${port} already answers: an old preview server would be tested instead of this build. Stop it first (ss -ltnp | grep ${port}).`);
  const child = spawn(process.execPath, args, { stdio: 'pipe', ...options });
  let exited = null;
  child.on('exit', (code, signal) => { exited = `${code ?? signal}`; });
  const stop = () => { if (exited === null) child.kill('SIGKILL'); };
  process.once('exit', stop);
  const url = `http://127.0.0.1:${port}`;
  // Ready = it accepts a TCP connection while still running. Not fetch():
  // Node's fetch refuses the Fetch standard's "bad ports" outright, and 4190
  // (browser-nodus) is one of them (ManageSieve); Chromium still loads it.
  for (let i = 0; i < 100; i++) {
    if (exited !== null) throw new Error(`vite preview on port ${port} exited (${exited}) before it answered.`);
    if (await portAnswers(port)) return { url, stop };
    await delay(50);
  }
  stop();
  throw new Error(`vite preview on port ${port} did not answer.`);
}
