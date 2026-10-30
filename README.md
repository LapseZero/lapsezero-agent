# lapsezero-agent

The deploy agent for [LapseZero](https://lapsezero.com). It runs on your server and pulls certificate deployments over outbound HTTPS, so the server doesn't need an open SSH port and LapseZero never holds your SSH credentials.

## Linux

1. You add an agent in the LapseZero console and run the install command it shows. The command downloads this binary, checks its SHA-256, exchanges a one-time token for a machine credential (stored in `/etc/lapsezero-agent/config.json`, mode 0600), and starts the `lapsezero-agent` systemd service.
2. The agent keeps one long-poll request open to LapseZero. When a certificate is ready for a deploy target on this server, it receives the files to write and the post-deploy command you configured in the console.
3. It deploys with all-or-nothing semantics:
   - reads every existing target file first; if any can't be read, nothing is written;
   - writes files in place (ownership and symlinks are kept);
   - runs the post-deploy command only after every file is written;
   - if a write or the command fails, restores the original files and runs the command again so the service goes back to the old certificate.
4. Before writing, it saves the original contents to `/var/lib/lapsezero-agent/journal.json` (mode 0600). If the agent dies mid-deployment, it restores those files on the next start.

When you click "Discover sites" in the console, the agent runs `nginx -T` once and reports, for each HTTPS server block, its `server_name`s, certificate and key paths, a suggested reload command, and public details of the current certificate (names, issuer, expiry, fingerprint). This Nginx configuration scan never reads or sends private key contents. It also flags certificates that certbot or acme.sh already renews, since both tools would overwrite each other's files. Nothing is changed on the server until you confirm deploy targets in the console.

If the server runs [1Panel](https://1panel.pro) (v1 or v2), the scan also lists its HTTPS websites through the local 1Panel API. 1Panel keeps website certificates in its own database and rewrites the files from it whenever a website's settings are saved, so for these websites the agent doesn't write files: it updates the certificate record in 1Panel, and 1Panel applies it to every website using that record and reloads OpenResty. If 1Panel reports an error, the agent writes the previous certificate back. This needs a 1Panel API key with `127.0.0.1` in its allowlist, entered in the LapseZero console; the agent finds the panel port from the running `1panel-core` (v2) or `1panel` (v1) process.

With agent v0.4.0 or later, discovery also lists certificates in running official [`jc21/nginx-proxy-manager`](https://nginxproxymanager.com/) Docker containers. Install the agent on the Docker host, where it can run `docker`; each container's stable name identifies the instance. Enter that instance's NPM email and password in the console. The account needs administrator access, or all-host visibility and certificate management permission, without an interactive login challenge. The agent connects locally using published ports or the Linux container network; you do not need to expose the admin port publicly.

For NPM, LapseZero takes over existing **Custom** certificate records. It preserves the certificate ID, name and Proxy Host, Redirection Host and Dead Host bindings, and refuses certificates managed by NPM's ACME renewal, incomplete records, and certificates used by Streams. Before each update it checks that the new certificate covers the original certificate names and every associated hostname, including disabled hosts. It uploads through the NPM API, reads back the result, runs `nginx -t` and reloads Nginx inside the container, then checks the live certificate for each enabled hostname. The upload API alone does not reload Nginx.

Before uploading it runs `nginx -t`, so an existing configuration error stops the deployment without changing anything. If the upload is accepted but the reload fails, the agent uploads the previous certificate again and reloads. NPM rejects expired certificates, so a previous certificate that has already expired cannot be restored; the deployment then fails with an error and the agent keeps handling other tasks. Private keys read from NPM are never sent back to LapseZero. Tested with official NPM 2.16.0, including shared host bindings, certificate rotation, chain formats and rollback.

### Updates and removal

The agent updates itself. When LapseZero reports a newer release, the agent waits until it's idle and downloads the release's `SHA256SUMS` and `SHA256SUMS.sig`, verifies the signature against the Ed25519 public key built into the binary, checks the binary's SHA-256, and runs the new binary's `version` to confirm it is the expected release. LapseZero lists both the GitHub and the Gitee release, and the agent tries the next one if a download or check fails, since a server may not reach the one for the account's region. It then keeps the current binary as `/usr/local/bin/lapsezero-agent.prev`, swaps in the new one and restarts. If the new version fails to start three times in a row, or can't reach LapseZero within five minutes, the agent switches back to the previous binary and skips that version for 24 hours.

If the agent is deleted or re-enrolled in the LapseZero console, its credential stops working for good. The agent then exits and the systemd service doesn't restart it. It never deletes itself; to remove it, run `lapsezero-agent uninstall` as root. Uninstall refuses to proceed while an interrupted deployment still has original files to restore.

The post-deploy command is configured in the LapseZero console and runs as root on this server. Only install the agent on servers whose LapseZero account you trust to run that command.

### Commands

```
lapsezero-agent enroll --server <url> --token <token>
lapsezero-agent run
lapsezero-agent uninstall
lapsezero-agent version
```

Logs go to the journal: `journalctl -u lapsezero-agent`.

## Windows IIS

The Windows client targets **Windows Server 2022 amd64**, with IIS on the same machine. It has passed end-to-end acceptance on a Server 2022 test machine, including recovery after forced kills and reboots.

Run the console's one-line PowerShell install command as Administrator. It downloads `lapsezero-agent-windows-amd64.exe` to a temporary directory and runs:

```powershell
.\lapsezero-agent-windows-amd64.exe install --server <url> --token <token>
```

The exe installs itself into `%ProgramFiles%\LapseZero Agent`, enrolls the host, and starts the automatic `LapseZeroAgent` Windows service as LocalSystem. SCM restarts the service after failures. Configuration and recovery state live under `%ProgramData%\LapseZero Agent`, accessible only to SYSTEM and Administrators. Logs go to Windows Event Viewer → Windows Logs → Application, source `LapseZeroAgent`.

Discovery reads local `applicationHost.config` directly. Choose an existing site and HTTPS binding in the console. Each target must have an exact SNI hostname and an exclusive HTTP.sys hostname:port mapping, using its current LocalMachine My or WebHosting store. Shared SNI mappings (including stopped sites and different binding IPs), exact IP:port shadowing, CCS, shared configuration and nonempty `siteDefaults/bindings` are rejected.

A deployment imports the PFX with a persistent, non-exportable machine private key, keeps intermediate certificates in CA, and uses the native HTTP.sys base-record update. It preserves all other base parameters and IIS `sslFlags`, and retains the previous certificate and private key. A single journal records `prepared` before the update and `finished` after a full readback. An interrupted, uncommitted update is rolled back only when the current state exactly matches this attempt's new state; external changes are reported as failures without overwriting them. Finished results are retried until acknowledged or declared stale before another task is polled.

TLS verification uses the binding's IP (127.0.0.1 for a wildcard), port and SNI hostname. Its result is reported separately and does not undo a committed deployment. After a restart, a committed result's TLS check is repeated before reporting.

To upgrade, run the same download-and-install command. An existing service is stopped, its exe replaced and restarted; configuration, credentials and recovery state are kept, and the token is not consumed again. Windows `update` is explicitly unsupported.

```powershell
& "$env:ProgramFiles\LapseZero Agent\lapsezero-agent.exe" uninstall
```

Uninstall stops and removes the service and deletes configuration and recovery state, including unfinished recovery. It prints the command to delete the remaining exe. Credential revocation stops the service without a restart loop.

## Build

```
./build.sh   # outputs Linux amd64/arm64 and Windows amd64 binaries, SHA256SUMS, SHA256SUMS.sig and github/ and gitee/ install.sh to dist/
go test ./...
```

## Release

Tag the version and run `VERSION=<tag> ./build.sh`. It signs `SHA256SUMS` with the release key at `~/.config/lapsezero/agent-signing.key` (override with `SIGNING_KEY`); agents only auto-update to releases signed with that key. Upload the binaries, `SHA256SUMS` and `SHA256SUMS.sig` to the same tag on both GitHub and Gitee, then upload `dist/github/install.sh` to GitHub and `dist/gitee/install.sh` to Gitee, each as `install.sh`. Each script has its own release URL built in and downloads the binary and `SHA256SUMS` from there, so uploading the wrong one sends users to the other platform.

Linux requires systemd. Windows targets Server 2022 amd64. Licensed under MIT.
