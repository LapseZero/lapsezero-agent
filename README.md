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

Use the Windows agent with **Windows Server 2016, 2019, 2022 or 2025 x64** and IIS on the same server.

1. Add an agent in the LapseZero console and choose Windows.
2. Open PowerShell as Administrator on the server and run the install command shown in the console.
3. Click **Discover sites**, select the HTTPS bindings you want to renew, and enable automatic renewal. Disable other certificate renewal tools for those sites.

The install command downloads `lapsezero-agent-windows-amd64.exe` and runs `install --server <url> --token <token>`. The agent starts automatically, including after a server restart, without anyone signing in.

### Supported sites

Each HTTPS binding must have a hostname without wildcards, **Require Server Name Indication** selected, and an SSL certificate in the local computer's **Personal** or **Web Hosting** certificate store. The certificate's private key must be accessible; if it is missing, import the certificate with its private key before scanning again.

Automatic renewal is not available when:

- another binding uses the same hostname and port, even on a different IP address or a stopped site;
- an HTTPS binding assigns a certificate by IP address on that port, so visitors may receive that certificate instead;
- the binding uses Centralized Certificate Store, or IIS uses shared configuration or default site bindings.

The console shows why a binding cannot be selected. Fix the issue in IIS and scan again.

### Certificate updates

The agent replaces the selected binding's certificate without restarting IIS or changing other site settings. Websites keep serving traffic, and old certificates and their private keys are kept on the server.

If an update fails or is interrupted, the agent restores the previous certificate where possible. It leaves changes made by someone else untouched. The console reports the outcome and any action you need to take; if the old certificate could not be restored, check the binding's certificate in IIS promptly.

After deployment, the agent checks which certificate IIS is serving. This result appears separately from the deployment result. If IIS serves a different certificate, check the certificate selected for that binding.

Logs are in **Windows Event Viewer → Windows Logs → Application**, under source **LapseZeroAgent**.

### Updates and removal

From v0.9.0 the Windows agent updates itself the same way as on Linux: it verifies the signed release, keeps the current binary as `lapsezero-agent.exe.prev`, swaps in the new one and lets the service restart it, switching back if the new version doesn't come up. Earlier versions need one manual upgrade: run the same install command again as Administrator. Reinstalling this way also works at any time; your settings are kept, and you do not need to add the server again.

To uninstall, open PowerShell as Administrator and run:

```powershell
& "$env:ProgramFiles\LapseZero Agent\lapsezero-agent.exe" uninstall
```

This stops and removes the agent without changing IIS settings or installed certificates. Follow the command's instructions to delete the remaining program files.

## Build

```
./build.sh   # outputs Linux amd64/arm64 and Windows amd64 binaries, SHA256SUMS, SHA256SUMS.sig and github/ and gitee/ install.sh to dist/
go test ./...
```

## Release

Tag the version and run `VERSION=<tag> ./build.sh`. It signs `SHA256SUMS` with the release key at `~/.config/lapsezero/agent-signing.key` (override with `SIGNING_KEY`); agents only auto-update to releases signed with that key. Upload the binaries, `SHA256SUMS` and `SHA256SUMS.sig` to the same tag on both GitHub and Gitee, then upload `dist/github/install.sh` to GitHub and `dist/gitee/install.sh` to Gitee, each as `install.sh`. Each script has its own release URL built in and downloads the binary and `SHA256SUMS` from there, so uploading the wrong one sends users to the other platform.

Linux requires systemd. Windows targets Server 2016, 2019, 2022 and 2025 amd64. Licensed under MIT.
