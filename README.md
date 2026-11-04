# trust

Command line for [Trust](https://certlocker.io). `trust` signs you in through the Edge login page, including 2FA, then calls the Edge API with that session. Edge enforces the permissions on your user. A missing permission comes back as HTTP 403.

The binary is `trust`. Releases cover Linux, macOS, and Windows on amd64 and arm64.

## Install

### Run directly from the Go repository

Requires Go 1.25 or newer. Clone the organisation repository and run commands
from its root; no installed binary or workspace report path is required:

```bash
git clone https://github.com/certlocker-io/trust-cli.git
cd trust-cli
go run ./cmd/trust --ui https://demo1.certlocker.io \
  --edge https://demo1.certlocker.io/rest auth login --no-browser --timeout 10m
```

Open the printed URL in a browser **on the same machine**, sign in and complete
2FA while leaving the terminal running. Omit `--no-browser` to launch the browser
automatically; the URL is always printed as a fallback.

```bash
go run ./cmd/trust auth whoami
go run ./cmd/trust tokens list
go run ./cmd/trust secrets list
go run ./cmd/trust auth logout
```

Login saves the UI/Edge URLs, so subsequent commands use the same deployment.
CLI account and permissions come from the signed-in Edge session. Gateway
`CERTLOCKER_TOKEN` and account-ID route configuration belong to the SDKs/Ansible.

### Build or install

```bash
go build -o bin/trust ./cmd/trust
./bin/trust version
# Or install directly from the organisation repository:
go install github.com/certlocker-io/trust-cli/cmd/trust@latest
```

`go install` puts `trust` in `$(go env GOPATH)/bin`. Every main-branch push runs
CI and uploads binaries for Linux, macOS and Windows, on amd64 and arm64, to
[GitHub Actions](https://github.com/certlocker-io/trust-cli/actions/workflows/ci.yml).
Only Linux amd64 runs the executable lifecycle smoke test; the other targets are
cross-build checks. Tagged `v*` releases run tests and GoReleaser to publish
archives plus checksums to [Releases](https://github.com/certlocker-io/trust-cli/releases).
Download the archive matching your OS/architecture and verify its SHA-256 against
`checksums.txt` before putting `trust` (`trust.exe` on Windows) on PATH.

## Sign in

```bash
trust auth login
```

The CLI listens on `127.0.0.1` and opens the Edge login page. Sign in with your password or SSO, then complete CertLocker 2FA in the browser. When Edge accepts the login it redirects back to the CLI. The session is stored locally. The login URL is always printed. Use `--no-browser` to skip automatic browser launch.

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

Login needs matching Edge and ui-edge CLI authentication support. The endpoints are `POST <edge-base>/security/v1/cli-authorize` and `POST <edge-base>/security/v1/cli-token`. Before opening the browser, the CLI checks the token endpoint with an empty request; missing routes, HTML responses and redirects produce an immediate error.

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

```bash
go test -race ./...
go vet ./...
python3 scripts/smoke_cli.py
```

The smoke script builds and executes the Linux CLI against a local HTTP fixture,
including PKCE browser callback/exchange, saved credentials at mode 0600, token
create/get/update/revoke, secret create/get/put/revoke, and logout cleanup. It
prints sanitized JSON proof. This is not live user login or live 2FA proof.
This evidence covers local contracts; live Edge authentication and management
create/update were not included in that run. See
[verification](docs/verification-2026-11-04.md).

### Real dev API verification (2026-11-04)

The isolated remote dev stack passed browser/2FA CLI login, PKCE rejection checks,
token and secret create/read/update, account-scoped Gateway access and tenant
isolation, actual Go and Rust smoke executables, Ansible create/repeat/lookup,
and DEVICE OIDC enrollment/exchange/suspension checks. Created fixtures were
revoked and the CLI logged out. See [sanitized proof](docs/dev-api-verification-2026-11-04.json).
This verifies the tested dev source plus the CLI route-access and shared DAO enum
conversion fixes; it does not assert a public deployment has been upgraded.
The reproducible scenario is Trust's `e2e/specs/dev-api-compatibility.phase.spec.ts`
(lifecycle phase 41). Public cloud OIDC providers are separate integration coverage.
