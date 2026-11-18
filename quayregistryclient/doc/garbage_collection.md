# Garbage collection, suppression des blobs et visibilité par l'API Quay

Ce document explique le fonctionnement du garbage collection (GC) de Quay, la
suppression des blobs et ce qu'il est possible — ou non — de récupérer pour un
dépôt donné via l'API. Il documente aussi la commande `gc-audit` de
`quayregistryclient`.

Les chemins de code cités sont ceux du dépôt **quay/quay** (branche `master` au
moment de la rédaction), pas ceux de ce dépôt d'outils.

---

## 1. Résumé

- Le GC Quay est **global au registre** mais il travaille **un dépôt à la fois**.
- Un tag supprimé ou expiré n'est pas supprimé immédiatement : il reste dans la
  **time machine** pendant `tag_expiration_s` secondes.
- `tag_expiration_s` est un réglage **par namespace** (utilisateur ou
  organisation), pas par dépôt. C'est la fenêtre de récupération des tags.
- Une fois la fenêtre écoulée, le tag devient **éligible au GC** :
  `date d'éligibilité = end_ts + tag_expiration_s`.
- Le GC supprime ensuite les manifests et les blobs qui ne sont plus référencés.
- L'API Quay expose les tags, les dates d'expiration, les politiques d'auto-prune
  et l'état du dépôt. Elle n'expose **pas** l'historique des blobs supprimés, ni
  de timestamp de GC par dépôt.
- `gc-audit` reconstitue l'état actuel : tags éligibles au GC, blobs référencés
  mais absents, manifests sparse et logs de suppression de tags.

---

## 2. Les trois mécanismes à ne pas confondre

| Mécanisme | Rôle | Portée | Réglage |
| --- | --- | --- | --- |
| **Auto-prune** | Marque des tags comme expirés selon une politique (`number_of_tags`, `creation_date`) | Dépôt ou organisation | Politiques `autoprunepolicy` |
| **Time machine** | Conserve un tag expiré/supprimé avant sa suppression définitive | Namespace (utilisateur ou organisation) | `removed_tag_expiration_s` / `tag_expiration_s` |
| **GC** | Supprime les tags éligibles, puis les manifests/blobs orphelins | Registre (worker global) | `GARBAGE_COLLECTION_FREQUENCY` |

### Auto-prune

L'auto-prune ne supprime pas immédiatement un tag. Il appelle
`oci.tag.delete_tag()`, ce qui **soft-delete** le tag en renseignant son
`lifetime_end_ms`. Le tag reste visible dans l'historique et récupérable pendant
la time machine.

Les politiques disponibles sont :

- `number_of_tags` : garder les N tags les plus récents ;
- `creation_date` : supprimer les tags plus vieux qu'une durée (par exemple
  `30d`).

Elles acceptent un `tagPattern` et `tagPatternMatches` pour filtrer les tags.

### Time machine

C'est le délai de grâce après l'expiration. Pendant cette période :

- le tag n'est plus « alive » ;
- il reste dans l'historique du dépôt ;
- il peut être restauré ;
- le GC ne le supprime pas encore.

### GC

Le GC est un worker séparé. Il ne connaît pas les politiques d'auto-prune : il
cherche les tags dont `lifetime_end_ms` est plus ancien que la fenêtre time
machine du namespace, puis supprime les tags, les manifests et les blobs
devenus orphelins.

---

## 3. Cycle de vie d'un tag

```
                 push / création
                        |
                        v
                 +--------------+
                 |    ALIVE     |  lifetime_end_ms = NULL ou futur
                 +--------------+
                        |
       suppression API, auto-prune, expiration planifiée
                        |
                        v
                 +--------------+
                 |   EXPIRED    |  end_ts = date d'expiration
                 |  (time       |  encore récupérable
                 |   machine)   |
                 +--------------+
                        |
          end_ts + tag_expiration_s <= maintenant
                        |
                        v
                 +--------------+
                 | GC-ELIGIBLE  |  le worker peut supprimer le tag
                 +--------------+
                        |
                passage du worker GC
                        |
                        v
                 +--------------+
                 |   DELETED    |  tag, manifests et blobs orphelins purgés
                 +--------------+
```

### `end_ts`

`end_ts` correspond à `Tag.lifetime_end_ms / 1000` :

- absent pour un tag vivant sans expiration planifiée ;
- futur si une expiration a été planifiée ;
- égal au moment de la suppression pour un tag supprimé via l'API ou l'auto-prune ;
- passé pour un tag expiré.

### `tag_expiration_s`

`tag_expiration_s` est la valeur `namespace.removed_tag_expiration_s` exposée par
l'API dépôt. Malgré son nom, ce n'est **pas** la durée de vie par défaut d'un
tag : c'est la durée de la **time machine**.

Valeurs usuelles :

| Valeur | Durée |
| --- | --- |
| `0` | aucune fenêtre de récupération |
| `86400` | 1 jour |
| `604800` | 1 semaine |
| `1209600` | 2 semaines (défaut Quay) |
| `2419200` | 4 semaines |

La valeur par défaut est `DEFAULT_TAG_EXPIRATION = "2w"`, et la base utilise
`1209600` comme valeur par défaut. Les options proposées dans l'UI sont
configurables via `TAG_EXPIRATION_OPTIONS` (`0s`, `1d`, `1w`, `2w`, `4w` par
défaut).

### Calcul de l'éligibilité

```text
gc_eligible_at = end_ts + tag_expiration_s
gc_eligible    = gc_eligible_at <= maintenant
```

Exemple avec `tag_expiration_s = 1209600` (14 jours) :

```text
T0          : tag supprimé / auto-pruné       -> end_ts = T0
T0 + 14j    : tag éligible au GC              -> gc_eligible_at
T0 + 14j+   : le worker GC peut le supprimer  (asynchrone, pas garanti à la seconde)
```

Un tag éligible n'est pas supprimé instantanément : le worker passe
périodiquement, traite un dépôt à la fois, et peut être retardé par un verrou
ou par la charge.

### Cas `tag_expiration_s = 0`

La time machine est désactivée : dès que `end_ts <= maintenant`, le tag est
éligible au GC. Il reste quand même visible jusqu'au passage du worker.

### Cas `tag_expiration_s = None`

Si l'API ne fournit pas la valeur, `gc-audit` ne peut pas calculer
`gc_eligible_at` et l'indique explicitement.

---

## 4. Ce que fait le GC dans Quay

### 4.1 Worker de GC

Fichier : `workers/gc/gcworker.py`.

Le worker :

1. choisit une politique de time machine parmi les valeurs distinctes des
   namespaces ;
2. cherche un dépôt contenant un tag expiré au-delà de cette fenêtre
   (`find_repository_with_garbage`) ;
3. prend un verrou `REPO_GARBAGE_COLLECTION_<repo_id>` ;
4. appelle `garbage_collect_repo(repository)`.

La fréquence par défaut est `GARBAGE_COLLECTION_FREQUENCY = 30` secondes. Le
verrou par dépôt empêche deux workers de purger le même dépôt simultanément.

### 4.2 Purge d'un dépôt

Fichier : `data/model/gc.py`.

`garbage_collect_repo()` :

1. supprime les tags « unrecoverable » :
   `lookup_unrecoverable_tags()` filtre les tags dont
   `lifetime_end_ms <= now - namespace.removed_tag_expiration_s` ;
2. supprime les uploads expirés ;
3. exécute `_run_garbage_collection()` :
   - parcours de l'arbre des manifests (manifest lists/indexes et enfants) ;
   - suppression des manifests qui ne sont plus référencés ;
   - suppression des labels orphelins ;
   - suppression des blobs orphelins.

Un manifest est conservé s'il est encore référencé par :

- un tag (`Tag.manifest`) ;
- un manifest parent (`ManifestChild.child_manifest`) ;
- un autre manifest via son champ `subject` (référence OCI).

### 4.3 Suppression des blobs

Fichier : `data/model/storage.py`, fonction `garbage_collect_storage()`.

La suppression physique d'un blob est très prudente :

- le blob doit être orphelin (`_is_storage_orphaned`) ;
- les lignes `ImageStoragePlacement`, `ImageStorageSignature` et `ImageStorage`
  sont supprimées dans une transaction ;
- le chemin physique n'est supprimé qu'après la transaction ;
- Quay vérifie qu'aucune autre ligne `ImageStorage` ne partage le même
  `content_checksum` (CAS) ;
- certains digests spéciaux (`SPECIAL_BLOB_DIGESTS`) sont conservés ;
- la suppression se fait sous le verrou `BLOB_DELETE_<checksum>` ;
- si le verrou n'est pas obtenu, la suppression physique est ignorée (choix
  sûr : le blob reste dans le stockage).

Conséquence importante : un blob partagé par plusieurs tags, manifests ou
dépôts n'est pas supprimé tant qu'une référence existe. Le GC ne supprime pas un
blob « parce qu'un tag a disparu » ; il le supprime quand plus aucun manifest ne
le référence.

### 4.4 Suppression d'un dépôt

`DELETE /api/v1/repository/{org}/{repo}` ne purge pas immédiatement :

1. le dépôt passe en `state=MARKED_FOR_DELETION` ;
2. un marqueur `DeletedRepository` est mis en file ;
3. `workers/repositorygcworker.py` prend le verrou `LARGE_GARBAGE_COLLECTION`
   et appelle `purge_repository()` ;
4. `purge_repository()` supprime tous les tags, manifests, blobs, politiques et
   métadonnées, **sans attendre la time machine** (`allow_non_expired=True`) ;
5. la ligne `Repository` est supprimée.

Tant que le worker n'est pas passé, le dépôt peut encore être visible via
l'API avec `state=MARKED_FOR_DELETION`. Une fois purgé, l'API renvoie `404`.

---

## 5. Ce que l'API expose pour un dépôt

### 5.1 État et time machine

```http
GET /api/v1/repository/{namespace}/{repository}
```

Champs utiles :

| Champ | Signification |
| --- | --- |
| `state` | `NORMAL`, `MIRROR`, `MARKED_FOR_DELETION`, etc. |
| `tag_expiration_s` | fenêtre time machine du namespace, en secondes |
| `is_public` | visibilité |

`tag_expiration_s` vient de
`namespace_user_removed_tag_expiration_s` dans la réponse API.

### 5.2 Tags

```http
GET /api/v1/repository/{namespace}/{repository}/tag/?onlyActiveTags=false&limit=100&page=1
```

Champs utiles :

| Champ | Signification |
| --- | --- |
| `name` | nom du tag |
| `manifest_digest` | digest du manifest pointé |
| `size` | taille des layers du manifest |
| `start_ts` | début de vie du tag |
| `end_ts` | fin de vie / expiration, en secondes |
| `expiration` | date formatée correspondante |
| `immutable` | tag immuable ou non |
| `is_sparse` | manifest list dont certains enfants sont absents |
| `present_child_count` | nombre d'enfants présents en base |
| `child_manifest_count` | nombre d'enfants déclarés |
| `child_manifests_presence` | map digest -> présence |

`onlyActiveTags=false` inclut les tags morts encore visibles. Les tags supprimés
définitivement par le GC ne sont plus retournés.

L'API retourne l'**historique complet** : un même nom de tag peut apparaître
plusieurs fois, avec un seul tag vivant et plusieurs versions mortes (une par
re-tag/reversion). C'est normal, pas un doublon de pagination. `gc-audit`
regroupe l'affichage par nom de tag et résume les versions historiques avec
`history=N` ; le JSON conserve toutes les lignes dans `tags.items`.

### 5.3 Manifest et layers

```http
GET /api/v1/repository/{namespace}/{repository}/manifest/{digest}
```

Champs utiles :

- `manifest_data` : JSON brut du manifest ;
- `is_manifest_list` ;
- `layers[]` avec `blob_digest`, `compressed_size`, `is_remote`, `urls` ;
- `config_media_type`.

Attention : `manifest_data` est la source de vérité pour les couches. La liste
`layers[]` de l'API est construite depuis la base ; si une ligne `ManifestBlob`
manque, elle peut être incomplète. `gc-audit` préfère donc les layers du manifest
brut et n'utilise `layers[]` qu'en secours.

### 5.4 Politiques d'auto-prune

```http
GET /api/v1/repository/{namespace}/{repository}/autoprunepolicy/
GET /api/v1/organization/{organization}/autoprunepolicy/
```

Réponse :

```json
{
  "policies": [
    {
      "uuid": "...",
      "method": "creation_date",
      "value": "30d",
      "tagPattern": "^v",
      "tagPatternMatches": true
    }
  ]
}
```

Méthodes : `number_of_tags`, `creation_date`.

### 5.5 Logs d'audit du dépôt

```http
GET /api/v1/repository/{namespace}/{repository}/logs?starttime=MM/DD/YYYY&endtime=MM/DD/YYYY
```

Kinds utiles :

- `autoprune_tag_delete` : tag supprimé par une politique d'auto-prune ;
- `delete_tag` : tag supprimé via l'API ;
- `permanently_delete_tag` : suppression hors time machine ;
- `delete_repo` : dépôt marqué pour suppression ;
- les événements de création/modification/suppression de politiques.

Le GC interne ne crée **pas** d'entrée d'audit pour les tags qu'il supprime.

### 5.6 Taille globale

```http
GET /api/v1/superuser/registrysize/
```

Réponse : `size_bytes`, `last_ran`, `queued`, `running`.

C'est une information **globale**, pas par dépôt. Il n'existe pas d'endpoint
`/gc` ou `/gc-status` par dépôt.

### 5.7 Registry V2

Pour vérifier la présence physique d'un blob :

```http
HEAD /v2/{namespace}/{repository}/blobs/{digest}
```

- `200` : blob présent ;
- `404` : blob absent ;
- `401/403` : credential ou scope insuffisant.

Le token s'obtient via :

```http
GET /v2/auth?service={registry}&scope=repository:{namespace}/{repository}:pull&account={user}
```

Un manifest peut encore être servi par Quay même si un ou plusieurs de ses blobs
sont absents : `GET /v2/{repository}/manifests/{digest}` lit les métadonnées, pas
les layers.

---

## 6. Ce que l'API n'expose pas

- **La liste des blobs supprimés** : aucune table d'historique, aucun endpoint.
- **Un timestamp de GC par dépôt** : le GC est global et asynchrone.
- **La position d'un dépôt dans la file GC**.
- **Les références d'un blob à travers les autres dépôts** : utile pour savoir si
  un blob est partagé, mais non exposé par l'API.
- **Les suppressions internes du GC** : les tags purgés par le GC ne produisent
  pas d'entrée `delete_tag` ou `autoprune_tag_delete`.
- **La suppression physique des blobs** :
  - log Quay au niveau `INFO` :
    `Removed blob <checksum> from <location> (path: ...) under namespace <ns> (repo: <repo>)` ;
  - éventuellement un `delete_marker` S3 ;
  - compteur Prometheus `quay_gc_storage_blobs_deleted`, **sans label de dépôt**.

Pour l'historique, il faut donc corréler :

- les logs Quay ;
- les logs/événements du stockage (S3 versioning, inventaire, lifecycle) ;
- la base Quay si l'on a un accès direct ;
- les logs d'audit pour les suppressions de tags initiées par un utilisateur ou
  l'auto-prune.

---

## 7. La commande `gc-audit`

`gc-audit` est une commande read-only de `quayregistryclient`. Elle n'appelle que
`GET` et `HEAD` ; elle ne supprime, n'expire et ne modifie rien.

### 7.1 Utilisation

```bash
# Un dépôt
./quayregistryclient gc-audit -r registry.example.com -i myorg/app

# Tous les dépôts d'une organisation, avec résumé par dépôt et total global
./quayregistryclient gc-audit -r registry.example.com -o myorg --all-repos \
    --only-problems
```

Avec `--all-repos`, la commande énumère les dépôts via
`GET /api/v1/repository?namespace=<org>`, exécute le même audit read-only sur
chacun, affiche une ligne de synthèse par dépôt puis les totaux. Les audits de
dépôts sont parallélisés par `--repo-jobs N` (défaut 4) ; chaque dépôt utilise
`--jobs N` (défaut 8) pour les `HEAD` de blobs. Les connexions HTTP sont
réutilisées par thread par défaut (`--persist-connection`) :
`--no-persist-connection` force une session par requête, par exemple pour
comparer ou contourner un proxy qui casse le keep-alive. En mode `--json`, elle produit
un document agrégé (`org`, `repositories[]`, `totals`, `errors`, `verdict`) et
non le détail des blobs de chaque dépôt. Réduire `--repo-jobs` et/ou `--jobs`
si le registry renvoie des `429` ou si le stockage sature.

Les totaux `blobs unique(repo-sum)` et `bytes(repo-sum)` sont des **sommes des
uniques par dépôt** : un blob partagé par deux dépôts est compté deux fois. Pour
le détail complet des blobs d'un dépôt, lancer `gc-audit` sans `--all-repos` avec
`--json` et consulter `blobs.items`.

Options principales :

| Option | Effet |
| --- | --- |
| `-i org/repo` | audit d'un seul dépôt |
| `-o org --all-repos` | audit de tous les dépôts de l'organisation |
| `--json` | sortie JSON sur stdout (complète pour un dépôt, agrégée pour `--all-repos`) |
| `--only-problems` | filtre la sortie texte (le JSON reste complet) |
| `--no-blob-check` | pas de `HEAD` sur `/v2`, verdict `INCOMPLETE` |
| `--max-tags N` | limite les tags audités (défaut 200, `0` = tous) |
| `--logs-days N` | ajoute les logs d'audit des N derniers jours |
| `--jobs N` | parallélisme des `HEAD` par dépôt (défaut 8) |
| `--repo-jobs N` | parallélisme des audits de dépôts avec `--all-repos` (défaut 4) |
| `--persist-connection` | réutilise une session HTTP par thread (activé par défaut) |
| `--no-persist-connection` | une session HTTP par requête (désactive le keep-alive) |
| `--fail-on-problem` | code retour 1 si findings |
| `--show-tags` | affiche les tags actifs même avec `--only-problems` |

### 7.2 Authentification

Deux credentials sont nécessaires :

1. **API `/api/v1`** : token OAuth, cookie de session ou web login (voir le
   README de `quayregistryclient`) ;
2. **registry `/v2`** : credential de pull, utilisé pour obtenir un token via
   `/v2/auth`.

Le second est acquis depuis `-u/-p`, depuis le credential stocké par
podman/docker, ou par un grant anonyme pour un dépôt public. S'il est absent, les
blobs sont marqués `unchecked` et le verdict est `INCOMPLETE`, pas `OK`.

### 7.3 Sortie

```text
### GC audit: myorg/app
  state                    = NORMAL
  tag_expiration_s         = 1209600 (14d)
  is_public                = False
  generated_at             = 2026-11-17T10:00:00Z

### retention / auto-prune
  repository policies:
    - method=creation_date value=30d tagPattern='^v' tagPatternMatches=True
  organization policies: none

### tags
  rows=42 unique_names=30 active_names=28 expired_rows=5 (pending=2 gc_eligible=3)
  one line per tag name; historical versions are summarized as history=N
  v1.0 active      digest=sha256:... size=12.3 MiB  history=3 gc_eligible_versions=1
  v1.1 gc-eligible digest=sha256:... size=8.1 MiB   end_ts=2026-10-01T... gc_after=2026-10-15T...
  v1.2 pending     digest=sha256:... size=4.0 MiB   end_ts=2026-11-10T... gc_after=2026-11-24T... history=2

### blobs
  check=on registry_token=basic unique=120 present=117 missing=3 ...
  MISSING sha256:... expected=12.3 MiB actual=? tags=v1.0 manifests=...
  SIZE_MISMATCH sha256:... expected=... actual=... tags=...

### sparse manifests (child manifests absent, not blob deletion)
  parent=sha256:... missing_child=sha256:... tags=latest

VERDICT: PROBLEM
  - blob sha256:... referenced by v1.0 is missing from storage
  - 1 tag(s) are already eligible for GC (informational, not a failure)
```

La section `### tags` affiche **une ligne par nom de tag**, pas une ligne par
version historique. `history=N` indique combien de versions (vivante + mortes)
existent pour ce nom ; `gc_eligible_versions=N` et `pending_versions=N`
résument les versions concernées. Utiliser `--json` pour obtenir le détail de
chaque version dans `tags.items`.

Avec `--all-repos`, la sortie devient une synthèse par dépôt puis un total :

```text
### gc-audit: myorg
  myorg/app        OK          tags rows=42 names=30 active=28 gc=2 | blobs unique=86 present=86 missing=0 mismatch=0 unchecked=0 | 837.2 MiB
  myorg/broken     PROBLEM     tags rows=8 names=8 active=8 gc=0 | blobs unique=12 present=10 missing=2 mismatch=0 unchecked=0 | 44.1 MiB

### summary: myorg
  repositories=2 with_findings=1 errors=0
  tags rows=50 unique_names=38 active_names=36 gc_eligible_rows=2 pending_rows=0
  blobs unique(repo-sum)=98 present=96 missing=2 size_mismatch=0 unchecked=0 skipped=0
  bytes(repo-sum)=881.3 MiB

VERDICT: PROBLEM
```

### 7.4 Interprétation du verdict

| Verdict | Signification |
| --- | --- |
| `OK` | aucun blob manquant/incohérent détecté pour les tags audités |
| `PROBLEM` | un blob référencé par au moins un tag **actif** est manquant, de taille incohérente, ou un manifest est illisible |
| `INCOMPLETE` | la vérification des blobs n'a pas pu être faite (pas de token `/v2`, `--no-blob-check`, ou `unchecked`) |

Cas des tags expirés :

- un blob manquant référencé **uniquement** par des tags expirés est classé en
  `WARNING`, pas en `PROBLEM` ;
- il reste affiché, car il peut révéler un problème de stockage ou un GC trop
  agressif, mais il ne fait pas échouer `--fail-on-problem`.

### 7.5 Codes retour

| Code | Signification |
| --- | --- |
| `0` | pas de finding (ou findings sans `--fail-on-problem`) |
| `1` | findings avec `--fail-on-problem` |
| `2` | erreur API ou usage |

### 7.6 Exemple JSON

```json
{
  "repository": "myorg/app",
  "state": "NORMAL",
  "tag_expiration_s": 1209600,
  "tags": {
    "total": 42,
    "active": 40,
    "expired_pending_gc": 2,
    "gc_eligible": 2,
    "items": []
  },
  "blobs": {
    "checked": true,
    "unique": 120,
    "present": 117,
    "missing": 3,
    "size_mismatch": 0,
    "unchecked": 0,
    "items": []
  },
  "problems": [],
  "warnings": [],
  "verdict": "OK"
}
```

---

## 8. Diagnostics typiques

### « Un tag existe mais ses layers sont introuvables »

```bash
./quayregistryclient gc-audit -r REGISTRY -i ORG/REPO --only-problems
```

- `missing` sur un tag actif : `VERDICT: PROBLEM` ;
- vérifier les lifecycle policies S3/GCS, une suppression manuelle, un nettoyage
  de bucket, ou un défaut de stockage ;
- si le tag est expiré et dans la time machine, c'est un `WARNING` ;
- le GC nominal ne doit pas supprimer un blob encore référencé par un manifest.

### « Le tag est expiré mais toujours là »

C'est normal tant que :

```text
end_ts + tag_expiration_s > maintenant
```

Attendre la fin de la time machine, puis le passage du worker GC. Vérifier aussi
que le worker GC est activé et qu'il n'est pas bloqué par un verrou.

### « Le dépôt supprimé est encore visible »

Vérifier `state` :

```bash
./quayregistryclient repo-view -r REGISTRY -i ORG/REPO
```

`state=MARKED_FOR_DELETION` signifie que la suppression est en file ; le
`RepositoryGCWorker` n'est pas encore passé.

### « L'auto-prune n'a rien supprimé »

Vérifier :

- la politique existe et s'applique au bon dépôt/org ;
- le `tagPattern` et `tagPatternMatches` ;
- les tags immuables (le GC et l'auto-prune les épargnent selon la configuration) ;
- la date de création des tags pour `creation_date`.

### « Le blob est-il partagé avec un autre dépôt ? »

L'API ne le dit pas. Le GC Quay vérifie globalement les références
`ManifestBlob` et les `content_checksum` `ImageStorage` avant de supprimer. Pour
un audit cross-repo, il faut interroger la base ou le stockage.

---

## 9. Limites et pièges

- `tag_expiration_s` est un réglage **de namespace** : deux dépôts de la même org
  ont la même valeur.
- Le nom `tag_expiration_s` est trompeur : ce n'est pas la durée de vie par
  défaut d'un tag, mais la fenêtre time machine.
- Un tag « GC-eligible » n'est pas supprimé à la seconde : le GC est asynchrone.
- Un blob absent ne prouve pas un bug du GC : cela peut venir d'une lifecycle
  policy du stockage, d'une suppression manuelle ou d'une panne.
- Les logs d'audit ne contiennent pas les digests de blobs supprimés par le GC.
- Le compteur Prometheus des blobs supprimés n'a pas de label de dépôt.
- `--no-blob-check` ne prouve pas que les blobs sont présents : le verdict est
  `INCOMPLETE`.
- `--only-problems` ne filtre que la sortie texte ; `--json` reste complet.

---

## 10. Références dans le code Quay

| Sujet | Fichier |
| --- | --- |
| Worker GC | `workers/gc/gcworker.py` |
| Sélection d'un dépôt avec du garbage | `data/model/oci/tag.py` (`find_repository_with_garbage`) |
| Tags unrecoverable / time machine | `data/model/oci/tag.py` (`lookup_unrecoverable_tags`) |
| Suppression tags/manifests/blobs | `data/model/gc.py` (`garbage_collect_repo`, `_run_garbage_collection`) |
| Suppression physique des blobs | `data/model/storage.py` (`garbage_collect_storage`) |
| Suppression d'un dépôt | `data/model/gc.py` (`purge_repository`) |
| Worker suppression dépôt | `workers/repositorygcworker.py` |
| Worker suppression namespace | `workers/namespacegcworker.py` |
| Auto-prune | `data/model/autoprune.py` |
| API tags | `endpoints/api/tag.py` |
| API dépôt / `tag_expiration_s` | `endpoints/api/repository_models_interface.py`, `endpoints/api/repository_models_pre_oci.py` |
| API politiques auto-prune | `endpoints/api/policy.py` |
| API logs | `endpoints/api/logs.py` |
| Configuration time machine | `config.py` (`DEFAULT_TAG_EXPIRATION`, `TAG_EXPIRATION_OPTIONS`) |
| Métriques GC | `util/metrics/prometheus.py` |

---

## 11. Références internes

- [`README.md`](../README.md) — commandes, authentification, mode read-only et
  `gc-audit`.
- [`quayregistryclient`](../quayregistryclient) — implémentation de `gc-audit`.
