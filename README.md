# lapsezero-agent

The deploy agent for [LapseZero](https://lapsezero.com). It runs on your server and pulls certificate deployments over outbound HTTPS, so the server doesn't need an open SSH port and LapseZero never holds your SSH credentials.

## How it works

1. You add an agent in the LapseZero console and run the install command it shows. The command downloads this binary, checks its SHA-256, exchanges a one-time token for a machine credential (stored in `/etc/lapsezero-agent/config.json`, mode 0600), and starts the `lapsezero-agent` systemd service.
2. The agent keeps one long-poll request open to LapseZero. When a certificate is ready for a deploy target on this server, it receives the files to write and the post-deploy command you configured in the console.
3. It deploys with all-or-nothing semantics:
   - reads every existing target file first; if any can't be read, nothing is written;
   - writes files in place (ownership and symlinks are kept);
   - runs the post-deploy command only after every file is written;
   - if a write or the command fails, restores the original files and runs the command again so the service goes back to the old certificate.
4. Before writing, it saves the original contents to `/var/lib/lapsezero-agent/journal.json` (mode 0600). If the agent dies mid-deployment, it restores those files on the next start.

When you click "Discover sites" in the console, the agent runs `nginx -T` once and reports, for each HTTPS server block, its `server_name`s, certificate and key paths, a suggested reload command, and public details of the current certificate (names, issuer, expiry, fingerprint). It never reads or sends private key contents. It also flags certificates that certbot or acme.sh already renews, since both tools would overwrite each other's files. Nothing is changed on the server until you confirm deploy targets in the console.

The post-deploy command is configured in the LapseZero console and runs as root on this server. Only install the agent on servers whose LapseZero account you trust to run that command.

## Commands

```
lapsezero-agent enroll --server <url> --token <token>
lapsezero-agent run
lapsezero-agent version
```

Logs go to the journal: `journalctl -u lapsezero-agent`.

## Build

```
./build.sh   # outputs Linux amd64/arm64 binaries, install.sh and SHA256SUMS to dist/
go test ./...
```

## Release

Tag the version, run `VERSION=<tag> ./build.sh`, and upload every file in `dist/` as assets of the same tag on both GitHub and Gitee. The install command downloads `install.sh`, the binary and `SHA256SUMS` from that release.

Requires Linux with systemd. Licensed under MIT.
