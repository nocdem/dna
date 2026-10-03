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

Options: `--prefix DIR` (default `/usr/local/bin`; the units' `ExecStart=` follows
it), `--config FILE` (installed as `/etc/nodus.conf` only when that file does
not exist), `--dry-run` (no change, no root needed).

The installer refuses — changing nothing — when the payload checksum fails,
when both layouts are enabled, when a split service is enabled but not asked
for, or when `nodus.addr_seq` exists both in the identity and the data
directory. It starts `nodus-core` first, waits (bounded) for its identity
files, then storage, then witness, and prints each unit's final state.

## Back to the combined server

```
systemctl disable --now nodus-core nodus-storage nodus-witness
systemctl enable --now nodus
```

or run `install.sh --layout combined`. Full procedure:
`nodus/docs/DEPLOY_RUNBOOK.md`, "tar.gz installer".
