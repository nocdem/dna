# Nodus installer tarball

Built by `nodus/deploy/make-dist.sh` from one build directory. Contents:

| File | What |
|---|---|
| `nodus-server` | combined server (`nodus.service`) — kept for rollback |
| `nodus-core`, `nodus-storage`, `nodus-witness` | the three-process node |
| `nodus-cli` | command-line client |
| `nodus.service`, `nodus-core.service`, `nodus-storage.service`, `nodus-witness.service` | systemd units |
| `install.sh` | the installer |
| `VERSION` | nodus version, arch, source commit, build type |
| `SHA256SUMS` | SHA-256 of every file above |

No config, no identity and no address of any node is in this tarball.
`/etc/nodus.conf` must exist, or be given with `--config <file>`.

## Install

```
sha256sum -c SHA256SUMS            # install.sh checks it again before anything
sudo ./install.sh --layout combined --dry-run     # print the plan
sudo ./install.sh --layout combined               # nodus.service
sudo ./install.sh --layout split                  # core + storage + witness
sudo ./install.sh --layout split --no-witness     # core + storage
sudo ./install.sh --layout split --no-storage     # core + witness
```

On a remote host run it inside `tmux` (or `screen`): an SSH drop interrupts it,
and the rollback commands it prints on Ctrl-C / SIGTERM / SIGHUP would go to a
terminal that is gone.

Options: `--prefix DIR` (default `/usr/local/bin`; the units' `ExecStart=` follows
it; not under `/home`, `/root`, `/tmp`, `/var/tmp` or `/run/user` — the units run
with `ProtectHome=true` and `PrivateTmp=true`), `--config FILE` (installed as
`/etc/nodus.conf` only when that file does not exist), `--allow-downgrade` (see
below), `--dry-run` (no change; root is not required, but the config must be
readable — `/etc/nodus.conf` as this installer writes it is mode 0600, so use `sudo`).

`deploy/build-nodus.sh` and `tools/nodus-update.sh` install to `/usr/local/bin`
only. A host installed with another `--prefix` must keep using `install.sh` for
every update — those two would put the new binaries where the units do not look.

The installer refuses — changing nothing — when:
- the payload checksum fails;
- `VERSION`'s arch is not this host's `uname -m`, or any packaged binary does not
  run here (`<binary> -h` must exit 0 and print this package's version — a missing
  shared library or too old a glibc stops it before any unit is touched);
- both layouts are enabled, or a split service is enabled but not asked for;
- `nodus-debug.service` (a `build-nodus.sh --debug` build on the same config and
  data directory) is enabled or running;
- a systemd drop-in (`*.conf` in `/etc/systemd/system/<unit>.service.d/` or
  `/run/systemd/system/<unit>.service.d/`) exists for any nodus unit;
- the installed nodus (in the prefix, or named by an installed unit's
  `ExecStart=`) is NEWER than this package, or its version cannot be read —
  unless `--allow-downgrade` is given;
- `nodus.addr_seq` exists both in the identity and the data directory.

It copies every binary and unit next to its destination as `<name>.new` while the
node still runs, then stops the units and renames all of them into place. It
starts `nodus-core` first, waits (bounded) for its identity files, then storage,
then witness, and prints each unit's final state.

**Going back to an older release.** Hard forks are height-activated
(`nodus/docs/DEPLOY_RUNBOOK.md` §2.2): once this chain has voted a hard fork, a
release older than the binary that introduced it stops following the chain.
`--allow-downgrade` exists for going back to a release that still carries every
hard fork voted on the chain — check §2.2's "Live hard forks" table first.

## Back to the combined server

```
systemctl disable --now nodus-core nodus-storage nodus-witness
systemctl enable --now nodus
```

or run `install.sh --layout combined`. The binaries stay the version last
installed; for an older version run that release's `install.sh --layout combined
--allow-downgrade`, under the hard-fork rule above. Full procedure:
`nodus/docs/DEPLOY_RUNBOOK.md`, "tar.gz installer".
