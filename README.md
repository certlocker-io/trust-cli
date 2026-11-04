# trust

Command line for [Trust](https://certlocker.io). `trust` signs you in through the Edge login page, including 2FA, then calls the Edge API with that session. Edge enforces the permissions on your user. A missing permission comes back as HTTP 403.

The binary is `trust`. Releases cover Linux, macOS, and Windows on amd64 and arm64.

## Install

### Download a release

Published tags build archives and `checksums.txt` on GitHub Releases. The archive name is `trust_<version>_<os>_<arch>`.

| OS | Archive | Binary |
| --- | --- | --- |
| macOS | `trust_<version>_darwin_amd64.tar.gz` or `trust_<version>_darwin_arm64.tar.gz` | `trust` |
| Linux | `trust_<version>_linux_amd64.tar.gz` or `trust_<version>_linux_arm64.tar.gz` | `trust` |
| Windows | `trust_<version>_windows_amd64.zip` or `trust_<version>_windows_arm64.zip` | `trust.exe` |

macOS or Linux:

```bash
# Example: macOS on Apple silicon, version 1.0.0.
curl -fsSL -o trust.tar.gz \
  https://github.com/Darren-Certlocker/trust-cli/releases/download/v1.0.0/trust_1.0.0_darwin_arm64.tar.gz
curl -fsSL -o checksums.txt \
  https://github.com/Darren-Certlocker/trust-cli/releases/download/v1.0.0/checksums.txt
shasum -a 256 -c checksums.txt --ignore-missing
tar -xzf trust.tar.gz
sudo install -m 755 trust /usr/local/bin/trust
trust version
```

On Linux, `sha256sum -c checksums.txt --ignore-missing` checks the archive. Put `trust` on `PATH`.

Windows, in PowerShell:

```powershell
Invoke-WebRequest -Uri https://github.com/Darren-Certlocker/trust-cli/releases/download/v1.0.0/trust_1.0.0_windows_amd64.zip -OutFile trust.zip
Expand-Archive trust.zip -DestinationPath .
# Move .\trust.exe onto a directory in $env:PATH
trust.exe version
```

`Get-FileHash trust.zip -Algorithm SHA256` should match the line for that zip in `checksums.txt`.

### From source

Go 1.25 or newer:

```bash
go install github.com/Darren-Certlocker/trust-cli/cmd/trust@latest
```

`go install` places `trust` in `$(go env GOPATH)/bin`.

## Sign in

```bash
trust auth login
```

The CLI listens on `127.0.0.1` and opens the Edge login page. Sign in with your password or SSO, then complete CertLocker 2FA in the browser. When Edge accepts the login it redirects back to the CLI. The session is stored locally. If the browser does not open, the command prints the URL.

```bash
trust auth whoami
trust auth logout
```

`whoami` prints the email, display name, groups, and permission names saved at login. Later calls send `Authorization: Bearer` with that session. On HTTP 401 the CLI renews the session once with the saved user token and retries.

Credentials and the saved URLs live under the OS config directory, mode `0600` on macOS and Linux:

| OS | Directory |
| --- | --- |
| macOS | `~/Library/Application Support/trust/` |
| Linux | `${XDG_CONFIG_HOME:-~/.config}/trust/` |
| Windows | `%AppData%\trust\` |

`credentials.json` holds the session. `config.json` holds the Edge and UI URLs used at login.

### Where it connects

| Flag | Environment | Default |
| --- | --- | --- |
| `--edge` | `TRUST_EDGE_URL` | `https://trust.certlocker.io/rest` |
| `--ui` | `TRUST_UI_URL` | `https://trust.certlocker.io` |

`--ui` is only used by `auth login`. A flag wins over the environment, which wins over `config.json`.

```bash
trust auth login \
  --ui http://127.0.0.1:5173 \
  --edge http://127.0.0.1:8080/edge/rest
```

`auth login` waits 5 minutes. `--timeout 10m` changes that.

Login needs an Edge and ui-edge build that expose `POST /edge/rest/security/v1/cli-authorize` and `POST /edge/rest/security/v1/cli-token`.

## Output

The default is a table. `--output json` prints indented JSON. This flag is global.

Errors from Edge are printed and the process exits 1. HTTP 403 means the signed-in user does not have the permission for that call.

## Hosts, certificates, secrets, probes, tokens, and AI agents

Each of `hosts`, `secrets`, `probes`, `tokens`, and `agents` has:

```text
list
get ID
create
revoke ID [--remove-associated]
suspend ID
unsuspend ID
resume ID
```

`unsuspend` and `resume` both call Edge `resume`. `revoke --remove-associated` also removes items tied to that asset.

`list` defaults to `--limit 50`. `--limit -1` asks Edge for as many rows as the store allows. `--skip` pages forward. `--name` is an exact match. `--status` is `ACTIVE`, `SUSPENDED`, `EXPIRED`, or `REVOKED`. `--group` keeps rows in that group. Edge already omits `REVOKED` rows from these lists.

```bash
trust hosts list --group ops --status ACTIVE
trust hosts get host_123
trust hosts suspend host_123
trust hosts unsuspend host_123
trust hosts revoke host_123 --remove-associated
```

`create` takes flags, or `--body file.json` for a full object. Flags overlay the file. Repeat `--group` for more than one group.

### Hosts

Permission prefix `HOST_`. Create uses `HOST_ADD`, list and get use `HOST_VIEW`, revoke `HOST_REVOKE`, suspend `HOST_SUSPEND`, unsuspend `HOST_RESUME`.

```bash
trust hosts create \
  --name edge-1 \
  --ip 10.0.0.5 \
  --port 22 \
  --os linux \
  --group ops \
  --secret secret_123 \
  --bastion bastion_123 \
  --description "edge host"
```

`--name` is required. `--ip` is `ip_address`, `--os` is `operating_system`, `--secret` is `secret_id`, `--bastion` is `bastion_id`.

### Certificates

`certificates` is also available as `certs`. Edge stores certificates separately from the suspend and revoke lifecycle used by hosts. List and get use `CERT_VIEW`. Generate and import use `CERT_ADD`. Download uses `CERT_DOWNLOAD`. Delete uses `CERT_DELETE`.

```bash
trust certificates list --status ACTIVE
trust certificates get cert_123
trust certificates generate --name edge --cn edge.example --group ops
trust certificates generate --name signing --cn signing.example --key-algorithm RSA --rsa-key-size 3072 --days 90
trust certificates download cert_123
trust certificates delete cert_123
trust certificates delete-expired
```

`generate` creates a self-signed certificate. `--key-algorithm` is `ECDSA` (default), `RSA`, or `ML_DSA`. ECDSA uses `--curve` `P-256` or `P-384`. RSA uses `--rsa-key-size` `2048`, `3072`, or `4096`. ML-DSA uses `--ml-dsa` `ML_DSA_44`, `ML_DSA_65`, or `ML_DSA_87`. `--hash` is `SHA256`, `SHA384`, or `SHA512` and is sent for RSA and ECDSA. `--days` defaults to 365 and must be from 1 to 8250. `--cn` is required. Optional subject flags are `--org`, `--ou`, `--locality`, `--state`, `--country`, and `--email`.

The private key is stored with the certificate and is not printed. `download` returns the public PEM only (`file_name` and `content`).

`create` imports an existing certificate. `--name` and the public PEM are required. Pass the PEM with `--public-cert-file` (`-` reads stdin) or `--public-cert`, and the key with `--private-key-file` or `--private-key`. `--domain` and repeated `--san` set `primary_domain` and `san_domains`.

`delete-expired` removes expired certificates in the account.

### Secrets

Permission prefix `SECRET_`.

```bash
trust secrets create --name db --type PASSWORD --group ops --secret-file ./db.txt
printf '%s' 's3cret' | trust secrets create --name db --type PASSWORD --secret-file -
```

`--type` is `PRIVATE_KEY`, `PEM`, `PASSWORD`, `CREDENTIALS`, or `CONFIGURATION`. `--secret` passes the value on the command line. `--secret-file -` reads stdin. The value is not printed again after create.

### Probes

Permission prefix `PROBE_`. Execute uses `PROBE_UPDATE`.

```bash
trust probes create \
  --name edge-tls \
  --ip edge.example \
  --port 443 \
  --frequency DAILY \
  --cert cert_123 \
  --group ops

trust probes run probe_123
trust probes run probe_123 --wait --timeout 2m
```

`run` posts `{ "id": "<id>" }` and returns Edge's acknowledgement, which does not include the TLS result. `--wait` polls `probe` detail until `result.at` changes, then prints the result. The command exits 1 when that result has `"success": false`. `--frequency` is `HOURLY`, `DAILY`, `WEEKLY`, or `MONTHLY`.

### Tokens

Permission prefix `TOKEN_`.

```bash
trust tokens create \
  --name ci \
  --type SECRET \
  --duration 12 \
  --unit HOURS \
  --protocol HTTPS \
  --secret secret_123 \
  --group ops \
  --single-use=false
```

`--type` is `CERTIFICATE`, `HOST`, `BASTION`, `SECRET`, `ROOT`, `MCP`, or `WILDCARD`. `--unit` is `MINUTES`, `HOURS`, `DAYS`, `WEEKS`, `MONTHS`, or `YEARS` and defaults to `DAYS` when `--duration` is set. Repeat `--protocol` (`SSH`, `SFTP`, `HTTPS`, `ACME`, `MCP`, `RDP`, `VNC`) and `--host`. `--name` and `--type` are required.

The created `id` is the credential. The CLI prints it once and tells you to store it.

`--cert`, `--bastion`, `--user`, `--cidr`, and `--auto-rotate` map to `cert_id`, `bastion_id`, `user_id`, `cidr`, and `auto_rotate`.

### AI agents

Permission prefix `AGENT_`. The Edge path is `ai-agent`.

```bash
trust agents create \
  --name deploy \
  --role role_reader \
  --risk LOW \
  --owner user_123 \
  --group ops \
  --description "deploy reader"
```

`--name` and at least one `--role` are required. `--risk` is `LOW`, `MEDIUM`, or `HIGH`. Create returns `id`, `name`, and `error_message`. A non-empty `error_message` exits 1.

## Audit

`AUDIT_VIEW` is required.

```bash
trust audit actions
trust audit list \
  --action HOST_ADD \
  --outcome SUCCESS \
  --severity INFO \
  --category CRUD \
  --actor USER \
  --email ada@example.test \
  --asset-type HOST \
  --asset-id host_123 \
  --group ops \
  --from 2026-11-01T00:00:00Z \
  --to 2026-11-02T00:00:00Z \
  --limit 50 \
  --skip 0
trust audit get audit_123
```

Filters become Edge query `musts`, a `groups` `ins` clause, and a `DATE` range on `occurred_at`. `--from` and `--to` are sent as you type them. Action, outcome, severity, category, actor, and asset type are uppercased. Email is lowercased.

`--outcome` is `SUCCESS`, `FAILURE`, or `DENIED`. `--severity` is `INFO`, `WARN`, or `HIGH`. `--category` is `AUTH`, `ACCESS`, `CRUD`, `POLICY`, `SYSTEM`, or `SECURITY`. `--actor` is `USER`, `SERVICE`, `SYSTEM`, `API`, `AI_AGENT`, or `OIDC`. `trust audit actions` prints the action names Edge knows, including `HOST_*`, `SECRET_*`, `TOKEN_*`, `PROBE_*`, `AI_AGENT_*`, and `ACME_AUTOMATION_*`.

## Automations

List and get use `ACME_AUTOMATION_VIEW`. Run uses `ACME_AUTOMATION_MODIFY`.

```bash
trust automations list --status ACTIVE
trust automations get automation_123
trust automations run automation_123 --type certificate --certificate cert_123 --token token_123
trust automations run automation_123 \
  --type challenge \
  --challenge-content "challenge-body" \
  --challenge-uri "http://example/.well-known/acme-challenge/token" \
  --wait
```

`--type` is `certificate` or `challenge`. A certificate run requires `--certificate` (`certificate_id`) and may include `--token` (`cert_token_id`). A challenge run requires `--challenge-content` and `--challenge-uri`. Edge enqueues the run and returns the queue row. `--wait` polls the automation detail until `last_run_at` changes, then prints `last_run_success`, `last_run_at`, and `console`. A recorded failure exits 1. `--timeout` defaults to 2 minutes.

## Permissions

Edge is the authority. The names below are the ones `whoami` shows and the ones a 403 is about.

| Area | Permissions |
| --- | --- |
| Hosts | `HOST_ADD`, `HOST_VIEW`, `HOST_REVOKE`, `HOST_SUSPEND`, `HOST_RESUME` |
| Certificates | `CERT_ADD`, `CERT_VIEW`, `CERT_DOWNLOAD`, `CERT_DELETE` |
| Secrets | `SECRET_ADD`, `SECRET_VIEW`, `SECRET_REVOKE`, `SECRET_SUSPEND`, `SECRET_RESUME` |
| Probes | `PROBE_ADD`, `PROBE_VIEW`, `PROBE_REVOKE`, `PROBE_SUSPEND`, `PROBE_RESUME`, `PROBE_UPDATE` |
| Tokens | `TOKEN_ADD`, `TOKEN_VIEW`, `TOKEN_REVOKE`, `TOKEN_SUSPEND`, `TOKEN_RESUME` |
| AI agents | `AGENT_ADD`, `AGENT_VIEW`, `AGENT_REVOKE`, `AGENT_SUSPEND`, `AGENT_RESUME` |
| Audit | `AUDIT_VIEW` |
| Automations | `ACME_AUTOMATION_VIEW`, `ACME_AUTOMATION_MODIFY` |

The CLI supports `update` (aliases `modify` and `put`) for hosts, secrets, probes, tokens, agents, and certificates. Lock, renew, and rotate operations are not implemented.

## Help

```bash
trust --help
trust hosts create --help
trust version
```


## Update assets and rollout verification (2026-11-04)

`hosts`, `secrets`, `probes`, `tokens`, `agents`, and `certificates` support
`update ID --body file.json`, with aliases `modify` and `put`. Pass `--body -`
to read JSON from stdin. Supply the full update form; this is not a JSON merge
patch. The command sets `id` and rejects mismatched IDs, arrays and null bodies.
Edge's contract is **POST resource/modify**, even when the CLI alias is `put`.

```bash
trust secrets update '<secret-id>' --body update-secret.json
trust tokens put '<token-id>' --body update-token.json
```

Keep secret files private and out of source control. Update output redacts secret
and private-key fields. Gateway `CERTLOCKER_TOKEN` credentials belong to the
Go/Rust/Java clients and Ansible; this management CLI needs an Edge browser login
and session. Select the deployment with `--ui`/`--edge` or `TRUST_UI_URL` and
`TRUST_EDGE_URL`; account selection comes from that authenticated Edge session.
The default UI is `https://trust.certlocker.io` and the Edge API base is
`https://trust.certlocker.io/rest`, matching the deployed UI configuration.
On 2026-11-04, that deployment supported ordinary UI login but returned 404 for
both `POST /rest/security/v1/cli-authorize` and `cli-token`. Its deployed UI bundle
also lacked CLI callback support. Deploy the matching Trust Edge and ui-edge
versions before using browser CLI login; completing ordinary UI 2FA alone cannot
complete the CLI handoff. Account-scoped Gateway requests also returned 404 while
legacy token metadata succeeded.

```bash
go test -race ./...
go vet ./...
python3 scripts/smoke_cli.py
```

The smoke script builds and executes the Linux CLI against a local HTTP fixture,
including PKCE browser callback/exchange, saved credentials at mode 0600, token
create/get/update/revoke, secret create/get/put/revoke, and logout cleanup. It
prints sanitized JSON proof. This is not live user login or live 2FA proof.
Live Edge authentication and management create/update remain unverified until a
CLI-enabled Edge/UI deployment and an account/browser login are available. See
[verification](docs/verification-2026-11-04.md).
