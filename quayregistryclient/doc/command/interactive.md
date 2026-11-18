# `interactive` — ncurses registry browser

`interactive` is a terminal UI for exploring a container registry that implements
the **Docker Registry HTTP API V2**. It shows the repository catalog as a tree and
lets you walk down to tags, manifests and blob metadata without downloading any
layer.

It is read-only: the command only issues `GET` and `HEAD` requests. It does not
need the Quay `/api/v1` API and works with any registry exposing `/v2/` (Quay,
Harbor, Distribution, …). For mirroring, GC or repository metadata, use
`mirror-get`, `mirror-scan`, `repo-view` or `gc-audit` instead.

```bash
./quayregistryclient interactive -r registry.example.com [-P 443] [-u user] [-p pass] [-d]
./quayregistryclient interactive -r registry.example.com -A
```

---

## Options

| Option | Description |
| --- | --- |
| `-r`, `--registry-url` | Registry host. Accepts `host`, `host:port` or `https://host[:port]`; the scheme is always HTTPS in the end. |
| `-P`, `--port` | Registry port, default `443`. A port embedded in `-r` takes precedence. |
| `-u`, `--username` | Registry username. |
| `-p`, `--password` | Registry password or robot-account token. |
| `-A`, `--anonymous` | Browse without credentials when the registry allows anonymous `/v2` access. Cannot be combined with `-u`/`-p`/`-T`. |
| `-d`, `--debug` | Print the equivalent `curl` command (credentials masked) for each request on stderr. |
| `-h`, `--help` | Show the help and exit. |

There is no `-T` option: the browser authenticates with HTTP Basic credentials
against the registry token endpoint, not with a pre-issued bearer token.

---

## Authentication

With `-A`/`--anonymous`, no credential is read or asked for: the command uses the
registry's anonymous token grant and sends no `Authorization` header. It can only
show what the registry exposes anonymously, which in practice means an open
registry (no auth at all) or a registry that grants anonymous catalog access.
Docker Hub and most Quay installations restrict `/v2/_catalog`, so an anonymous
browser there reports `No repositories visible anonymously.` — not an error in
the tool. `-A` cannot be combined with `-u`/`-p`/`-T` and exits with code 2 if
it is.

Without `-A`, the command needs a username and password. They come from, in
order:

1. `-u` / `-p`;
2. the credential stores shared with podman/docker (`REGISTRY_AUTH_FILE`,
   `$XDG_RUNTIME_DIR/containers/auth.json`, `~/.config/containers/auth.json`,
   `~/.docker/config.json`), replayed byte-for-byte like podman does;
3. an in-UI login prompt if nothing usable was found.

The login prompt asks for the username and then the password (echoed as `*`).
If authentication fails, the screen shows `Authentication failed. Check
credentials.` and the registry's own error is written to stderr before that.

`QRC_TOKEN`, `QRC_COOKIE`, `QRC_USERNAME` and `QRC_PASSWORD` are `/api/v1`
settings and are not used here. Because a Bearer token is used, the password is
only sent to the registry's token endpoint, never with the catalog or manifest
requests.

The window title shows `(anonymous)` in anonymous mode.

---

## Registry requests

| Step | Request | Notes |
| --- | --- | --- |
| Registry token | `GET /v2/auth?account=<user>&service=<host>` | Basic auth, returns the catalog token. In `-A` mode: same endpoint without `Authorization`, using the anonymous grant. |
| Repository token | `GET /v2/auth?…&scope=repository:<repo>:pull` | One token per repository, cached until shortly before `expires_in`. Anonymous mode sends no credentials; a refusal means requests go out unauthenticated. |
| Catalog | `GET /v2/_catalog` | All pages are followed through the `Link` header at startup. |
| Tags | `GET /v2/<repo>/tags/list` | One request per repository, cached for the session. |
| Digest | `HEAD /v2/<repo>/manifests/<tag>` | Digest read from `Docker-Content-Digest`. |
| Manifest | `GET /v2/<repo>/manifests/<digest>` | One request advertising all four manifest media types in a single `Accept` header. |
| Blob metadata | — | Read from the manifest JSON; blob content is never downloaded. |

All requests use a finite timeout, and connections are kept alive in
thread-local `requests` sessions. When no token is available (anonymous registry,
anonymous grant refused), requests are sent without an `Authorization` header
instead of `Bearer None`.

---

## The tree

```
Registry
└── org/                 directory: first path component of a repository
    ├── app              image:     the rest of the path (org/app)
    │   ├── v1           tag
    │   │   ├── sha256:… (linux/amd64)   manifest (multi-arch index)
    │   │   └── sha256:… (linux/arm64)
    │   └── latest       tag
    │       ├── sha256:… layer           blob
    │       └── sha256:… config          blob
    └── app2
```

Only the **first** path component becomes a directory node; deeper levels remain
part of the image label. For example `team/project/app` is shown as directory
`team/` containing image `project/app`.

Icons:

| Icon | Node type |
| --- | --- |
| `[R]` | Registry root |
| `[+]` / `[-]` | Collapsed / expanded directory |
| `[I]` | Image (repository) |
| `[T]` | Tag |
| `[M]` | Manifest (platform entry of a multi-arch index) |
| `[B]` | Blob (layer or config) |
| `[?]` | Unknown node type |

Image names get a `(N tags)` suffix once their tag count has been fetched in the
background. Directories and images are colour-coded; the selected row is
reverse-video and search hits are highlighted.

---

## Keys

| Key | Action |
| --- | --- |
| `Up` / `Down` | Move the selection. |
| `Space` | Expand or collapse the selected node (directory, image, tag or manifest). |
| `Enter` | Show details for an image, tag or blob. |
| `b` | Leave the details view and return to the tree. `q` does the same there. |
| `/` | Enter a search term. `Enter` validates, `Esc` cancels, backspace edits. |
| `n` / `N` | Jump to the next / previous search match. |
| `q` | Quit the browser. |

The status line shows the shortcut reminder and a `[current/total]` match
counter when a search is active.

`Enter` on a directory, the registry root or a manifest does nothing (manifests
are expanded with `Space`). Search terms are limited to 40 characters.

---

## Expansion is lazy

Nothing below the catalog is loaded at startup. Each `Space` loads exactly one
level:

| Selected node | What expansion does | Network cost |
| --- | --- | --- |
| Directory | Reveals the image nodes built from the catalog. | None (catalog already in memory). |
| Image | Lists its tags. | Repository token (cached) + `GET /tags/list`. |
| Tag | Resolves the digest, then shows platform manifests for an index or blob metadata for a single-manifest image. | One `HEAD` + one `GET` (both cached afterwards). |
| Manifest | Lists its layers and config as blob nodes. | None if the tag was expanded first (manifest cached); otherwise one `GET`. |
| Blob / registry | Nothing. | None. |

Collapsing a node only hides its already-loaded children; expanding it again does
not issue new requests. A `Loading …` line is displayed while an expansion is
waiting for the registry.

---

## Search

`/` searches **repository names**, case-insensitively and as a substring, over
the catalog loaded at startup. Matching paths are opened automatically so their
image rows become visible; the first match is selected and `n`/`N` cycle through
the rest. Tags, manifests and blobs are not searched.

Search does not filter the tree (non-matching rows stay visible); it highlights
matches and moves the cursor. If nothing matches, the tree is left unchanged and
the match counter disappears.

---

## Details view

`Enter` opens a read-only summary:

* **Image** — repository name, total number of tags (first ten listed), and an
  approximate size.
* **Tag** — repository, tag and resolved digest. The digest shows `Loading...`
  if the tag has never been expanded.
* **Blob** — size in bytes and media type.

The image size is an **estimate**, labelled with `~`. It sums the config and
layer sizes of the first three tags, expanding multi-arch indexes into their
platform manifests. It is not the repository's storage usage: tags share layers,
and tags beyond the first three are ignored. A repository whose manifests cannot
be read shows `Size: unavailable`.

---

## Performance and caching

The browser is designed so that network latency does not block navigation:

* **Catalog once.** `/v2/_catalog` is fetched (all pages) at startup and kept in
  memory. Startup time is therefore proportional to the catalog size; see
  [Limitations](#limitations).
* **Session caches.** Tags, digests, manifests and repository information are
  cached for the lifetime of the process. Re-visiting an expanded node costs no
  request.
* **Token cache.** Repository-scope tokens are reused until 30 seconds before
  the registry-reported expiry (5 minutes when `expires_in` is absent).
* **Keep-alive.** One `requests.Session` is reused by the UI thread, plus one
  per background worker, instead of a new TLS handshake per call.
* **One request per manifest.** The four accepted manifest media types are sent
  in a single `Accept` header, so resolving a tag costs one `HEAD` and one `GET`,
  not four of each.
* **Tag counts off the UI thread.** Counts for images in the viewport are queued
  to six daemon workers and rendered when they arrive. Requests and drawing never
  run in the same thread. Workers are daemons, so quitting (`q`) is immediate even
  if a request is still in flight.
* **No idle repaint.** The event loop wakes every 200 ms to collect finished tag
  counts, but only redraws when a count arrived or a key was pressed.

Failures are treated as empty results: a tag list, digest or manifest that cannot
be fetched leaves the node empty, and the node is marked loaded so it is not
retried during the session. Restart the command to retry.

---

## Limitations

* **Catalog access is required.** Many registries restrict `/v2/_catalog` to
  administrators or disable it. Without it the UI reports `No repositories
  found.` (or `No repositories visible anonymously.` with `-A`); check with
  `./quayregistryclient list-catalog -r <host>`.
* **The whole catalog is loaded at startup.** There is no server-side filter or
  incremental paging in the UI. On a registry with tens of thousands of
  repositories, the initial load can take a long time and use noticeable memory.
* **Anonymous mode depends on the registry.** `-A` only works when the registry
  grants an anonymous token and exposes the catalog. Docker Hub does not expose
  a public `/v2/_catalog` (and does not implement V1 search), and Quay normally
  requires a credential for the catalog, so `-A` is mainly useful for open
  Distribution registries or public catalog endpoints.
* **Tag-list pagination is not followed.** If a registry paginates
  `/tags/list` by default, only the first page is shown.
* **Blobs are metadata only.** Layer contents are not downloaded or previewed;
  use `get-blob` for that.
* **Search is catalog-only.** It does not look into tags, manifests or blobs and
  has no regex or fuzzy matching.
* **Size is an estimate** from up to three tags, not a storage or quota figure.
* **No mirroring/GC data.** Those live in the Quay API; see
  [`../garbage_collection.md`](../garbage_collection.md) and the `mirror-*`
  commands.
* **Requires an interactive terminal.** It is an ncurses application: running it
  without a TTY fails at initialisation.

---

## Troubleshooting

| Symptom | Likely cause / action |
| --- | --- |
| `Authentication failed. Check credentials.` | Wrong login, expired robot token, or a registry whose token endpoint rejects the account. Test with `./quayregistryclient list-catalog -r <host> -u <user> -p <pass>`. |
| `No repositories found.` | `/v2/_catalog` returned 401/403 or an empty list; the token may be valid but the catalog may be restricted. |
| `No repositories visible anonymously.` | `-A` was used but the registry does not expose its catalog (or anonymous token grant) without credentials. Retry with `-u`/`-p` or without `-A`. |
| A directory is empty | The catalog contained no repository under that prefix. |
| A tag/image stays empty | Scope-token, `HEAD` or `GET` failure. The registry's error is printed on stderr; restart to retry. |
| TLS/certificate error | The registry certificate is not trusted. Run `get-server-certificate -r <host>` and install the CA. |
| Startup is slow | Large catalog, many pages, or a slow registry. The number of pages is proportional to the repository count. |
| Screen corrupted after an error message | A diagnostic line was written while curses was active. Press any key to trigger a redraw, or restart. |
| Need to see the API calls | Re-run with `-d 2>debug.log`; stderr keeps the masked `curl` lines out of the UI. |

Interrupting with `Ctrl+C` restores the terminal and exits; `q` is the normal
way to leave the browser.
