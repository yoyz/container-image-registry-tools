# quayregistryclient

A Python CLI for inspecting and troubleshooting a container registry that speaks the
**Docker Registry HTTP API V2** and the **Red Hat Quay API** (`/api/v1`), including its
mirroring configuration.

It targets the situations where `podman` confirms a registry is healthy but tells you
nothing about *why*: which repositories actually exist, which ones are mirrors, what
each mirror is synchronised against, which robot account it uses, and what a
synchronisation error means once Quay has decrypted it.

Current version: **0.5.0**.

## Features

* **Registry navigation** — list repositories (paginated) and tags, walk an org tree.
* **Deep inspection** — image digests (SHA), raw JSON manifests, individual blob layers,
  TLS certificate of the endpoint.
* **Quay mirroring inventory** — per-repository mirror configuration plus health,
  perimeter and robot-account aggregates (`mirror-scan`), and the repository /
  organisation auto-prune (garbage-collection retention) policies (`mirror-get`).
* **GC / blob audit** — read-only `gc-audit` for one repository: tags pending GC,
  auto-prune policies, blob presence checked with `HEAD /v2/.../blobs/...`, sparse
  manifest-list children and optional tag-deletion audit logs.
* **Authentication** — Basic auth, bearer tokens, a Quay *session cookie*, and automatic
  discovery of credentials already stored by podman/docker. See
  [Authentication](#authentication).
* **Read-only by default** — destructive commands ship disabled behind a single
  switch. See [Read-only mode](#read-only-mode).
* **Output hygiene** — data on stdout, diagnostics on stderr, secrets masked by default.
* **Debug mode** — prints the equivalent `curl` command for every request, with
  credentials masked, so an API call can be reproduced by hand.
* **Interactive mode** — ncurses tree browser over the registry.
* **Bash completion** — dynamic completion of commands, options, repositories and tags.

## Prerequisites

* Python 3.x
* `requests`

```bash
pip install requests
```

Python 3.10+ is not required: on older 3.x, `get-server-certificate` prints the
leaf certificate instead of the full chain (and says so on stderr).

## Usage

```bash
./quayregistryclient <COMMAND> [OPTIONS]
```

### Options

| Option | Description |
| --- | --- |
| `-r`, `--registry-url` | Registry URL (e.g. `quay.io`, `registry.example.com`). |
| `-P`, `--port` | Registry port (default `443`). |
| `-u`, `--username` | Registry username. |
| `-p`, `--password` | Registry password. |
| `-i`, `--image-name` | Image / repository name, as `org/name`. |
| `-t`, `--tag` | Tag name (default `latest`). |
| `-T`, `--token` | Bearer token (OAuth / app / robot token). |
| `-D`, `--digest` | Image digest (`sha256:…`). |
| `-a`, `--apipath` | API path, for the raw `browse-api` / `set-api-key-value` commands. |
| `-K`, `--key` / `-V`, `--value` | Key and value for `set-api-key-value`. |
| `-o`, `--org` | Organisation name. |
| `-q`, `--query` | Search term for `search-v1`. |
| `-d`, `--debug` | Debug mode: equivalent `curl` commands and diagnostics on stderr. |
| `--show-secrets` | Do not mask secret-bearing fields in API responses. |
| `--orgs a,b,c` | Candidate organisations for `org-exists`. |
| `--pages N` | Page limit for `search-v1`. |
| `--desc` | `search-v1`: also show repository descriptions. |
| `--only-problems` | `mirror-scan`: keep only repositories whose mirror is unhealthy. |
| `--max-repos N` / `--offset N` | `mirror-scan`: window over an organisation. |
| `--i-am-deleting-all-repo` | Required confirmation for `delete-all-repo`. |
| `-h`, `--help` | Show the help; also works per command (`mirror-scan -h`). |
| `--generate-completion` | Print a bash completion script and exit. |

> Where credentials are omitted, the tool loads them from the credential stores it
> shares with podman — see [Credential lookup](#credential-lookup).

### Environment variables

| Variable | Effect |
| --- | --- |
| `QRC_USERNAME` / `QRC_PASSWORD` | Credentials for the web sign-in (`/api/v1`). |
| `QRC_TOKEN` | Bearer token for `/api/v1`. |
| `QRC_COOKIE` | Replays a Quay session cookie; **no sign-in is attempted at all**. |
| `QRC_ALLOW_STORE_WEB_LOGIN` | Whether a credential read from a credential store may be replayed to `POST /api/v1/signin` (default `1`). |
| `REGISTRY_AUTH_FILE` | Overrides the credential store location (podman convention). |

Prefer environment variables over `-u`/`-p` on a shared machine: command lines are
visible to other users through `ps`.

---

## Command reference

All commands are listed together; the **Effect** column tells what a command can change.
Commands marked *disabled* are read/write and are refused until read-only mode is
turned off.

| Command | API surface | Requires | Effect |
| --- | --- | --- | --- |
| `list-catalog` | `/v2/_catalog` | `-r` | read |
| `list-tags` | `/v2/…/tags/list` | `-r -i` | read |
| `list-all` | `/v2/_catalog` + tags | `-r` | read |
| `get-image-digest` | manifest `HEAD` | `-r -i -t` | read |
| `get-image-manifest` | raw manifest JSON | `-r -i -D` | read |
| `get-blob` | blob layer | `-r -i -D` | read |
| `get-server-certificate` | TLS handshake | `-r` | read |
| `search-v1` | registry V1 search (what `podman search` calls) | `-r` | read |
| `interactive` | `/v2`, ncurses tree browser | `-r` | read |
| `quay-config` | public `/config` | `-r` | read — anonymous, no credential needed |
| `org-exists` | anonymous per-org probe | `-r --orgs a,b,c` | read — anonymous; answers 200 = org exists, 404 = absent |
| `whoami` | `/api/v1/user/` | `-r` + API credential | read |
| `list-org-repos` | `/api/v1/…/repository` | `-r -o` + API credential | read |
| `org-robots` | `/api/v1/…/robots` | `-r -o` + API credential | read |
| `repo-view` | `/api/v1/repository/<org>/<name>` | `-r -i` + API credential | read |
| `mirror-get` | repository + mirror config + **auto-prune (GC) policies** | `-r -i` + API credential | read |
| `mirror-scan` | per-repo mirror inventory, with `HEALTH` / `PERIMETRE` / `ROBOTS` aggregates | `-r -o` + API credential | read |
| `gc-audit` | tags pending GC, auto-prune policies, blob presence via `/v2` `HEAD`, sparse children | `-r -i` + API credential (registry pull credential for blob checks) | read |
| `browse-api` | any `/api/v1` path, `GET` | `-r -T -a` | read |
| `quay-api-discovery` | `/api/v1/discovery` | `-r -T` | read |
| `quay-api-listuser` | `/api/v1/superuser/users/` | `-r -T` | read |
| `delete-repo` | `DELETE` repository | `-r -i -T` | **read/write — disabled** |
| `delete-tag` | `DELETE` tag | `-r -i -t -T` | **read/write — disabled** |
| `delete-all-repo` | `DELETE` every repository of an org, after a 10 s countdown | `-r -u -p -T --i-am-deleting-all-repo` | **read/write — disabled** |
| `set-api-key-value` | `PUT` config key | `-r -T -a -K -V` | **read/write — disabled** |
| `quay-api-create-user` | `POST /api/v1/superuser/users/` | `-r -T -u` | **read/write — disabled** |
| `quay-api-delete-user` | `DELETE /api/v1/superuser/users/<user>` | `-r -T -u` | **read/write — disabled** |
| `quay-api-change-userpassword` | `PUT /api/v1/superuser/users/<user>` | `-r -T -u -p` | **read/write — disabled** |

Two notes on this table:

* **API surface matters more than the name.** The V2 commands authenticate through the
  registry protocol; the `/api/v1` commands authenticate through Quay's web/JSON API,
  which does not accept the same credential. `quay-api-*` and `browse-api` are the
  older generation and always want an explicit `-T token`; the mirroring commands use
  any of the three [API authentication modes](#apiv1-authentication).
* **A credential probe is never a read-only action.** Fetching a token on `/v2/auth`
  and signing in on `POST /api/v1/signin` create server-side session and audit events.
  They never create, modify or delete a registry object, but a failed sign-in *does*
  have side effects — see the warning under
  [Web sign-in](#3-web-sign-in-session-cookie).

> **Garbage collection.** Quay runs GC cluster-wide and the API exposes **no
> per-repository GC timestamp** and **no deleted-blob history**. The per-repository
> signals are the auto-prune (retention) policies, the time-machine window
> (`tag_expiration_s`) and the repository state: `MARKED_FOR_DELETION` (see
> `repo-view`) means it is queued for GC. `gc-audit` reconstructs what the API can
> answer: tags already eligible for GC (`end_ts + tag_expiration_s`), tags still
> inside the window, auto-prune policies, and whether the blobs referenced by the
> tags still exist in storage. It cannot say *when* or *by what* a blob was deleted:
> Quay only writes that to its own logs (`Removed blob ... under namespace ...`) and
> to the Prometheus counter `quay_gc_storage_blobs_deleted`, which has no repository
> label. A missing blob on an active tag is therefore a finding, not proof of a Quay
> GC bug — check S3/GCS lifecycle rules and storage-side deletion too. See
> [`doc/garbage_collection.md`](../doc/garbage_collection.md) for the full model
> (time machine, auto-prune, manifest/blob deletion, API limits and `gc-audit`).

### Quirks this tool encodes

These are registry behaviours, not tool bugs, and they explain most "the tool returns
nothing" reports:

* **`/v2/_catalog` can come back empty on Quay while the orgs are full.** The catalogue
  only lists what the credential may see, so it is empty to an anonymous request and
  needs a real credential otherwise. `list-org-repos -o <org>` (API) is the reliable
  way to enumerate an organisation.
* **An empty catalogue is also what a wrong credential looks like.** Anonymous reads are
  often enabled, so a bad or absent credential yields an empty list on `/v2/_catalog`
  rather than an error. The tool warns on stderr when a candidate credential is rejected
  (and then replays it anyway, leaving the registry to answer), but a `/v2` listing can
  still come back silently empty — an empty `list-catalog` is not proof of an empty
  registry. The `/api/v1` commands are stricter: they check for a usable credential
  first and stop with exit code 5 instead of printing a believable `0`.
* **`podman search` works on a registry whose `/v2/_catalog` you cannot read.** V1 search
  authenticates through the token grant; `search-v1` covers that case.
* **API errors carry no plaintext secrets.** Quay returns upstream mirror credentials
  already decrypted; that decryption happens server-side. The tool masks them
  (`--show-secrets` reveals them).

---

## Authentication

The tool deals with two distinct authentication surfaces, and confusing them is the
most common way to get a 401.

### V2 (registry protocol): `GET /v2/` then a token grant

```
GET /v2/                       401 + WWW-Authenticate: realm=…&service=…&scope=…
GET <realm>?service=…&scope=…  Authorization: Basic <user:pass>   -> { "token": … }
GET /v2/<name>/…               Authorization: Bearer <token>
```

The stored credential is replayed **verbatim**, exactly as podman does — the tool never
re-encodes it. This matters because two stores can hold different encodings of the same
account, and a re-encoded value is silently rejected while the stored one is accepted.

### Credential lookup

Credential files are read in podman's precedence order, and every candidate is offered
to the registry until one is accepted:

1. `$REGISTRY_AUTH_FILE`
2. `$XDG_RUNTIME_DIR/containers/auth.json` — podman's native store
3. `~/.config/containers/auth.json`
4. `~/.docker/config.json`

The file is matched on the bare hostname: a trailing `/` and a `:443` suffix are both
stripped, since stores typically key entries by host alone. Secrets are never printed,
logged, or written back.

### /api/v1 authentication

Quay's JSON API does **not** accept HTTP Basic: it answers
`401 {"error_type": "invalid_token"}` even for a credential the very same registry
accepts on `/v2`. Three modes are supported, tried in this order:

| # | Mode | Credential sent | Sign-in attempt? |
| --- | --- | --- | --- |
| 1 | `-T token` / `QRC_TOKEN` | `Authorization: Bearer …` | no |
| 2 | `QRC_COOKIE` | `Cookie: session=…` | **no** |
| 3 | `-u/-p` / `QRC_USERNAME`/`QRC_PASSWORD` | session cookie + `X-CSRF-Token` | **yes** |

Modes 2 and 3 are the same mechanism: after a successful sign-in, `/api/v1` is reached
with a **session cookie**, not with a password. The Ansible collection
`infra.quay_configuration` authenticates exactly this way, which is why an Ansible job
succeeds where a Basic-auth call 401s.

#### 1. Token

The OAuth/app token of a Quay application (or a robot token) — the same value an
Ansible playbook passes as `quay_api_token`.

#### 2. Session cookie — `QRC_COOKIE`

Replays an existing browser session. Useful when the account cannot or should not sign
in again from a script, or simply to avoid touching the sign-in counters:

```bash
export QRC_COOKIE='session=<value from the browser>'
./quayregistryclient whoami   -r registry.example.com
./quayregistryclient mirror-scan -r registry.example.com -o myorg
```

How to get the value: in the browser's developer tools, on a logged-in Quay tab, copy
the `session` cookie (Application → Cookies). The cookie carries the session, so treat
it as a password: pass it through the environment, never on the command line, and never
commit it.

Behaviour of this mode, and its two limits:

* **No sign-in is attempted** — the tool goes straight to the API with the cookie, so a
  Quay account-lock counter is never touched. When `QRC_COOKIE` is set, the web sign-in
  of mode 3 is skipped entirely, even if credentials are available.
* **No CSRF token is sent.** The sign-in response also yields an `X-CSRF-Token` that the
  tool keeps and replays only for a session it established itself. A replayed browser
  cookie therefore supports `GET` requests; anything that mutates state needs mode 1 or
  3. (Not restrictive today: the mutating commands are disabled by
  [read-only mode](#read-only-mode) anyway.)
* **The cookie expires** on the server's schedule. A `401` after a period of success
  normally means it is time to copy a fresh one.

#### 3. Web sign-in (session cookie)

The tool reproduces the browser login flow:

```
GET  /csrf_token                    -> {"csrf_token": …}          (Quay 3.16+)
                                     -> window.__token in /        (older Quay)
POST /api/v1/signin                 X-CSRF-Token: …  {"username", "password"}
     -> 200, Set-Cookie: session=…  and X-Next-CSRF-Token: …
GET  /api/v1/…                      Cookie: session=…  X-CSRF-Token: <next>
```

The cookie and the rotating CSRF token live in the process memory only: they are never
written to disk, printed, or logged. The session is reused for every subsequent request
of the run.

> **WARNING — this mode has a side effect.** A failed `POST /api/v1/signin` increments
> `invalid_login_attempts` on that account. When the account is a shared service account
> — in a mirrored estate, typically the same credential that every mirror passes as
> `--src-creds` — a mistyped password can lock mirroring platform-wide, not just your
> session. Use `QRC_COOKIE` or `QRC_TOKEN` when you only need to read.

Because credentials discovered in a credential store are the operator's own
`login:pass`, they are replayed to the sign-in endpoint **by default**. Set
`QRC_ALLOW_STORE_WEB_LOGIN=0` to forbid that and require an explicit `-u`/`-p` or a
token:

```bash
QRC_ALLOW_STORE_WEB_LOGIN=0 ./quayregistryclient whoami -r registry.example.com
```

### No credential found

When no mode can produce a credential, API commands stop with exit code 5 **before**
sending anything, rather than printing a believable empty result. `/v2` commands
(`/v2/_catalog`, `list-catalog`, `search-v1`, …) keep working: they use the registry
protocol, not the API.

---

## Read-only mode

Mutating commands are compiled in but refused at startup, **before any network call**, so
a mistyped command cannot damage a registry. The refusal goes to stderr, names the
offending command, points at the `READ_ONLY` switch, and exits with code 4.

The lock lives at the top of the source:

```python
READ_ONLY = True
```

Set it to `False` only when you intend to mutate a registry, and only after re-checking
the target: on a mirrored estate the same command line can be run against a hub *and*
against a regional registry that holds the content customers pull.

When the lock is off, `delete-all-repo` still requires
`--i-am-deleting-all-repo` **and** displays a 10-second countdown on stderr before
the first request; `Ctrl+C` during the countdown aborts with exit code 130 and
deletes nothing.

---

## Output hygiene

* **stdout carries data only**; diagnostics, hints and debug output go to stderr.
* **Secrets are masked by default.** JSON keys matching
  `password` / `secret` / `token` / `credential` / `api_key` / `apikey`, and the fields
  Quay returns already decrypted (`external_registry_username`, the upstream LDAP login
  used by mirrors), are replaced with a masked marker. `--show-secrets` reveals them.
* **Debug mode (`-d`) masks credentials too.** The `curl` equivalent it prints shows
  `Authorization: ***` rather than a replayable value.
* **Quoting note:** messages contain `!` (e.g. `!!` before a warning). In interactive
  bash, `!` triggers history expansion — double-quote arguments that contain it.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | success |
| 1 | certificate retrieval failure, `delete-all-repo` without `--i-am-deleting-all-repo`, or `gc-audit --fail-on-problem` with findings |
| 2 | missing parameters |
| 3 | credential refused by the registry at the token-grant step (`-d` shows the registry's own message; re-run `podman login`) |
| 4 | command refused by [read-only mode](#read-only-mode) |
| 5 | no usable `/api/v1` credential in any of the three modes |
| 130 | `delete-all-repo` countdown interrupted with `Ctrl+C` (nothing deleted) |

---

## Interactive mode

An ncurses tree browser over the registry: Registry → Directory → Image → Tag →
Manifest → Blob.

```bash
./quayregistryclient interactive -r registry.example.com [-P 443] [-u user] [-p pass]
```

| Key | Action |
|-----|--------|
| `Space` | Expand / collapse a directory or image |
| `Up` / `Down` | Move in the list |
| `Enter` | Show details of an image, tag or blob |
| `b` | Back from a details view |
| `/` | Search for an image name |
| `n` / `N` | Next / previous match |
| `q` | Quit |

## Bash completion

Completion is dynamic: it queries the registry for repository and tag names.

```bash
./quayregistryclient --generate-completion > ~/.bash_completion_quay
source ~/.bash_completion_quay
echo 'source ~/.bash_completion_quay' >> ~/.bashrc
```

| After | You get |
| --- | --- |
| `./quayregistryclient [TAB]` | command names |
| `./quayregistryclient list-tags -[TAB]` | the options valid for that command |
| `./quayregistryclient list-tags -r reg -i [TAB]` | repositories fetched from `reg` |
| `./quayregistryclient list-tags -r reg -i org/app -t [TAB]` | tags of `org/app` |

Completion resolves credentials through the same lookup as the tool, and takes them from
the environment (`QRC_TOKEN`, …) rather than the command line, so they never appear in
`ps`. If nothing is configured it reports `No token available` instead of completing.

## Quick start against a Quay registry

```bash
# 0. Is the registry answering, and how is it configured? (anonymous)
./quayregistryclient quay-config -r registry.example.com

# 1. Which identity am I, and what can I see?
./quayregistryclient whoami       -r registry.example.com
./quayregistryclient list-catalog -r registry.example.com

# 2. Walk an organisation through the API
./quayregistryclient list-org-repos -r registry.example.com -o myorg
./quayregistryclient org-robots     -r registry.example.com -o myorg

# 3. Mirrors: one repository, then the whole org
./quayregistryclient repo-view  -r registry.example.com -i myorg/rhel
./quayregistryclient mirror-get -r registry.example.com -i myorg/rhel
./quayregistryclient mirror-scan -r registry.example.com -o myorg --only-problems
```

`mirror-get` on a mirror shows the upstream URL, the robot used, the last
`sync_status` and `last_update` — Quay's own words, which is where the difference
between *misconfigured* and *upstream gone* becomes visible — followed by the
auto-prune (GC retention) policies of the repository and of its organisation.

```bash
# 4. Keep only the mirrors that need attention
./quayregistryclient mirror-scan -r registry.example.com -o myorg --only-problems --max-repos 50
```

### GC / blob audit

`gc-audit` is the read-only diagnostic for “a tag exists but its layers are gone”
(see also [`doc/garbage_collection.md`](../doc/garbage_collection.md)):

```bash
# Metadata + full blob presence check (HEAD /v2/.../blobs/<digest>)
./quayregistryclient gc-audit -r registry.example.com -i myorg/app

# CI-friendly: only the findings, exit 1 when a referenced blob is missing
./quayregistryclient gc-audit -r registry.example.com -i myorg/app \
    --only-problems --fail-on-problem

# Fast metadata-only pass (no /v2 blob request), plus 7 days of tag-deletion logs
./quayregistryclient gc-audit -r registry.example.com -i myorg/app \
    --no-blob-check --logs-days 7

# Machine-readable output
./quayregistryclient gc-audit -r registry.example.com -i myorg/app --json
```

It prints:

* repository `state`, `tag_expiration_s` and auto-prune policies (repository and
  organisation);
* tags with `end_ts`, plus the computed GC-eligibility date
  `end_ts + tag_expiration_s`; the text output groups the full tag history by
  name (one line per tag, `history=N` for older versions), while JSON keeps every
  version in `tags.items`;
* every unique blob digest referenced by the tags, checked with `HEAD` (status
  `present`, `missing`, `size_mismatch`, `unchecked` or `skipped`) and the tags /
  manifests that reference it;
* sparse manifest-list children (missing child manifests, normal for sparse mirror
  indexes) and manifest metadata errors;
* optionally, recent `autoprune_tag_delete` / `delete_tag` audit entries.

Blob checks need a `/v2` pull credential in addition to the `/api/v1` credential.
It is acquired from `-u/-p`, the stored podman/docker credential, or an anonymous
token grant for a public repository; without it the command still reports the
metadata and marks the blobs `unchecked` (verdict `INCOMPLETE`, not `OK`).

Options: `--json`, `--only-problems` (text output only; JSON stays complete),
`--no-blob-check`, `--max-tags N` (default 200, `0` = all), `--logs-days N`
(default `0`), `--jobs N` (default 8), `--fail-on-problem`, `--show-tags`. Exit
codes: `0` no failure, `1` findings with `--fail-on-problem`, `2` fatal API/usage
error.
