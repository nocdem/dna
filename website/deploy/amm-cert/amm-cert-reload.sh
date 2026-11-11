#!/bin/sh
# Installed as /usr/local/sbin/amm-cert-reload (root, mode 755). Reloads nginx so it serves the certificate lego has
# just written under /etc/lego-amm/certificates/ (ssl_certificate in amm-https.conf is a fixed path that nginx reads
# only at load time). It tests the configuration first and reloads only if `nginx -t` passed, because this nginx also
# serves kayraninyeri.com. Any failure exits non-zero, so lego (as its deploy hook) and systemd (as ExecStartPost of
# nodus-amm-cert.service) record it.
#
# Why a script and not `--deploy-hook "nginx -t && systemctl reload nginx"`: lego v5.6.0 splits a hook string on
# whitespace and runs it WITHOUT a shell (cmd/internal/hook/hook.go:23-25: `parts := strings.Fields(hook)`,
# `exec.CommandContext(ctxCmd, parts[0], parts[1:]...)`), so `&&` would be handed to nginx as an argument. The hook
# given to lego is this script's path, a single word.
set -eu
nginx -t
systemctl reload nginx
