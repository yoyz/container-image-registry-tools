# `search-v2` — catalog search (podman's V2 fallback)

The Docker Registry **V2 protocol has no search endpoint**. When `podman search`
gets a 404 from the deprecated `/v1/search`, it falls back to paging through
`/v2/_catalog` and matching repository names locally. `search-v2` implements
that fallback, including anonymous access to registries with a public catalog.

```bash
./quayregistryclient search-v2 -r registry.fedoraproject.org -A -q http
./quayregistryclient search-v2 -r registry.example.com -q myapp --pages 3
```

Use `search-v1` instead when the registry implements the old V1 search API
(Quay does); `search-v1` also returns descriptions and visibility.

---

## Options

| Option | Description |
| --- | --- |
| `-r`, `--registry-url` | Registry host, required. |
| `-P`, `--port` | Registry port, default `443`. |
| `-q`, `--query` | Case-insensitive substring matched against repository names. Empty shows the whole catalog. The syntax is `-q http` (or `--query http`); a bare `q=http` is rejected as an unknown argument. |
| `--pages N` | Maximum number of catalog pages to fetch (`0`, the default, means all). |
| `-A`, `--anonymous` | Do not use or ask for credentials. |
| `-u`, `--username` / `-p`, `--password` | Registry credentials when the catalog is private. |
| `-T`, `--token` | Pre-issued Bearer token. Cannot be combined with `-A`. |
| `-d`, `--debug` | Print the equivalent `curl` commands (masked) on stderr. |
| `-h`, `--help` | Show the help and exit. |

`-A` cannot be combined with `-u`, `-p` or `-T`; that is rejected with exit
code 2.

---

## What it does

1. Optionally obtains a token:
   * `-A`: tries the anonymous grant `GET /v2/auth?service=<host>`, then falls
     back to no `Authorization` header if the registry refuses;
   * `-u`/`-p` (or a stored podman/docker credential): `GET /v2/auth` with
     Basic auth, then `Authorization: Bearer …` on the catalog;
   * `-T`: the token is used directly;
   * no credential at all: unauthenticated catalog request.
2. Fetches `GET /v2/_catalog`, following the `Link: <…>; rel="next"` headers
   until the last page or `--pages`.
3. Deduplicates and filters repository names with a case-insensitive substring
   match, then sorts them naturally (`app-9` before `app-10`).
4. Prints one `NAME` line per match and a page/result footer.

There is no server-side search and no per-page query parameter: every page must
be fetched before the local filter can be complete. `--pages 1` is useful for a
quick look at the beginning of a large catalog; it is not a "first page of
results" (matches later in the catalog are simply not seen).

Names are printed as repository paths (`f29/httpd`), not prefixed with the
registry host (podman prints `registry.fedoraproject.org/f29/httpd`). This keeps
them directly usable with `-i`/`-t` in the other commands.

The catalog carries **no descriptions and no visibility flag**, so the output
has only a `NAME` column. Use `search-v1` or the Quay API (`list-org-repos`,
`repo-view`) when descriptions or private/public state matter.

Example output:

```text
### /v2/_catalog q='http'  results=1  pages=9
  NAME
  f29/httpd
# total: 1 result(s) from 9 catalog page(s)
```

---

## Anonymous access

`-A` is what makes the Fedora registry work:

```bash
./quayregistryclient search-v2 -r registry.fedoraproject.org -A -q http
```

It skips `-u`/`-p`, the credential-store lookup and any login prompt, asks for an
anonymous service token, and sends plain unauthenticated requests if that grant
is refused. Whether the search can see anything is entirely up to the registry:

| Registry | Anonymous catalog |
| --- | --- |
| `registry.fedoraproject.org` | yes (9 pages for the full catalogue at the time of writing) |
| Open Distribution / Harbor project with public catalog | depends on configuration |
| Quay (including `quay.io`) | normally no: `/v2/_catalog` needs a credential |
| Docker Hub (`docker.io`) | no public `/v2/_catalog`; use the Hub search API or `docker search` |

An anonymous search on a registry that hides its catalog returns no match. A
`401`/`403` is printed on stderr and the command exits 1; it is not a silent
empty result.

---

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Catalog fetched successfully, with or without matches. |
| 1 | Catalog request/JSON failure, or an unusable redirect. |
| 2 | Missing `-r`, or `-A` combined with `-u`/`-p`/`-T`. |
| 3 | A supplied credential was refused by the token endpoint. |

---

## Limitations

* **Full catalog traversal.** With `--pages 0`, the command reads every catalog
  page and keeps all names in memory. Large registries cost time and bandwidth;
  this is exactly the behaviour `podman search` has when it falls back to V2.
* **Name matching only.** Tags, descriptions and blob metadata are not searched.
* **No ranking.** Results are sorted naturally, not by relevance.
* **Catalog visibility.** If the registry hides `/v2/_catalog`, no search can
  enumerate it; there is no alternative V2 endpoint.
* **No descriptions.** V1 search returns them; the V2 catalog does not.
* **Rate limits.** A full crawl can hit registry rate limits, especially on
  anonymous endpoints.

---

## Troubleshooting

| Symptom | Likely cause / action |
| --- | --- |
| `Failed to get images: 401` / `403` | Catalog is private or anonymous access is disabled. Retry with `-u`/`-p` (or without `-A`). |
| `(no result)` but the repository exists | It may be beyond `--pages`, or the catalog does not list it (Quay hides it from `/v2/_catalog`). |
| Empty result on Docker Hub | Docker Hub has no public `/v2/_catalog`; use `docker search` or the Hub API. |
| Slow command | Full catalog crawl. Cap it with `--pages N` or narrow the registry. |
| `--anonymous cannot be combined with -u/-p/-T` | Remove the credentials or remove `-A`. |
| Need to see the requests | Re-run with `-d`; masked `curl` lines go to stderr. |
