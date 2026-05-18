# StoreGit

A serverless file storage service built on **Cloudflare Pages Functions** and the **GitHub Contents / Git Data APIs**. Each registered user is backed by their own GitHub repository. The operator deploys a single Cloudflare Pages project; users bring their own GitHub repository and personal access token.

---

## Table of Contents

- [Architecture](#architecture)
- [Authentication](#authentication)
- [File Storage](#file-storage)
- [File Operations](#file-operations)
- [Security Model](#security-model)
- [Rate Limiting](#rate-limiting)
- [Blocked File Types](#blocked-file-types)
- [File Size Limits](#file-size-limits)
- [API Reference](#api-reference)
- [Operator Deployment](#operator-deployment)
- [User Registration](#user-registration)
- [License](#license)

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                  Cloudflare Pages (Operator)                 │
│                                                              │
│   User A  ──►  GitHub Repo A  (user file storage)           │
│   User B  ──►  GitHub Repo B  (user file storage)           │
│   User C  ──►  GitHub Repo C  (user file storage)           │
│                                                              │
│   Registry Repo  ──►  Stores all user account records       │
└─────────────────────────────────────────────────────────────┘
```

The operator maintains one **registry repository** on GitHub that stores all user account records as JSON files. Each user owns and controls their own separate **storage repository**; the operator never has direct write access to user data beyond what the user's encrypted token permits.

All API logic runs inside a single Cloudflare Pages Function at `functions/api/[[path]].js`. There is no origin server, database, or persistent compute outside of Cloudflare KV (used for rate limiting).

---

## Authentication

### Session Lifecycle

- **Login** — credentials are verified server-side; on success a signed, encrypted session token is set as an `HttpOnly` cookie.
- **Session token format** — the payload is encrypted with **AES-256-GCM** and signed with **HMAC-SHA256**. The client receives an opaque blob; the plaintext is never exposed.
- **Session TTL** — 8 hours. Tokens are validated on every authenticated request.
- **Logout** — the session cookie is cleared server-side; the client receives a `Set-Cookie` header that expires immediately.

### Password Hashing

Passwords are hashed with **PBKDF2-SHA256** using the Web Crypto API (`crypto.subtle`).

| Parameter | Value | Rationale |
|---|---|---|
| Hash function | SHA-256 | — |
| Iterations (current) | 100,000 | 600,000 would exceed Cloudflare Worker CPU limits (~5–15 ms at 100k vs. ~60–200 ms at 600k, which causes a Worker kill) |
| Iterations (legacy) | 50,000 | Accounts created before the 100k migration; auto-upgraded on next successful login |
| Salt | 16 bytes, random per user | `crypto.getRandomValues` |
| Output | 256-bit derived key | — |

Legacy accounts (hashed at 50,000 iterations) are transparently re-hashed to 100,000 iterations on the next successful login without any user action.

### Timing Attack Mitigation

- All credential comparisons use constant-time equality checks.
- On a failed login for an unknown username, a dummy `pbkdf2Hash` call is executed against a random salt to ensure the response time is indistinguishable from a valid user lookup, preventing username enumeration via timing.

---

## File Storage

### Repository Layout (per user)

```
<folder>/                              ← configurable at signup (default: uploads/)
├── document.pdf                       ← small files (≤ 5 MB), stored via Contents API
├── archive.zip                        ← small files (≤ 5 MB), stored via Contents API
├── .chunks/
│   └── large-video.mp4/
│       ├── large-video.mp4.part0      ← 10 MB chunk
│       ├── large-video.mp4.part1
│       └── large-video.mp4.part2
└── .manifests/
    ├── large-video.mp4.json           ← per-file chunk manifest
    └── _index.json                    ← master index: filename → { totalSize, totalChunks }
```

Chunks, manifests, and the index file are filtered out of all file listing responses. Users interact only with logical filenames.

### Small Files (≤ 5 MB)

Uploaded directly via the **GitHub Contents API** (`PUT /repos/{owner}/{repo}/contents/{path}`), encoded as Base64. The SHA of the resulting blob is stored and used for subsequent update and delete operations.

### Large Files (> 5 MB)

Uploaded in **10 MB chunks** via the **GitHub Git Data API**:

1. Each chunk is uploaded as a Git blob (`POST /git/blobs`).
2. A tree is constructed containing all chunk blobs (`POST /git/trees`).
3. A commit is created referencing the tree (`POST /git/commits`).
4. The branch ref is updated to point at the new commit (`PATCH /git/refs/heads/{branch}`).

A manifest file (`<folder>/.manifests/<filename>.json`) records the blob SHA, size, and part index for each chunk. The master index (`_index.json`) maps each chunked filename to its total size and total chunk count.

**Chunk pre-slicing** — files above the 5 MB threshold are pre-sliced into `Blob` segments and cached in a `WeakMap` on the client as soon as they are queued, so no re-slicing is needed at upload time.

**Maximum chunk count** — 512 chunks × 10 MB = ~5 GB theoretical maximum per file.

### Download and Reassembly

All downloads are proxied through the Cloudflare Worker. GitHub repository URLs are never sent to the client.

- **Small files** — fetched via the Contents API and streamed to the client.
- **Chunked files** — the Worker reads `_index.json` to identify chunked files, fetches each part blob in sequence, concatenates them, and streams the complete file. The client receives a single uninterrupted byte stream.

A `Content-Length` header is set on the response where the total size is known.

---

## File Operations

### Upload

| Path | API used | Condition |
|---|---|---|
| Direct | GitHub Contents API | File ≤ 5 MB |
| Chunked | GitHub Git Data API | File > 5 MB |

Chunked uploads use three endpoints: `/api/upload-chunk` (one call per part) followed by `/api/upload-finalize` (writes the manifest and updates `_index.json`).

### Delete

- **Small file** — issues a `DELETE` to the GitHub Contents API using the stored blob SHA.
- **Chunked file** — deletes every part blob from `.chunks/<filename>/`, the per-file manifest from `.manifests/`, and removes the entry from `_index.json`, all in a single atomic commit.

### File Listing

`GET /api/files` returns metadata for all top-level files in the user's upload folder. Internal paths (`.chunks/`, `.manifests/`, `.storegit`) are excluded from all responses. For chunked files, metadata (name, total size) is sourced from `_index.json` rather than the raw GitHub tree.

---

## Security Model

| Concern | Implementation |
|---|---|
| Password storage | PBKDF2-SHA256, 100,000 iterations, 16-byte random salt per user |
| GitHub token storage | AES-256-GCM; encryption key derived from `TOKEN_SECRET` + username via HKDF-SHA256 |
| Session tokens | AES-256-GCM encrypted payload + HMAC-SHA256 signature; 8-hour TTL |
| GitHub repository URLs | Never sent to the client; all file transfers are proxied server-side |
| Brute-force protection | 5 login attempts per IP / 15-minute window; 10 per username; 3 signup attempts per IP |
| Timing attack mitigation | Dummy `pbkdf2Hash` on unknown username; constant-time equality for all comparisons |
| File extension blocklist | Enforced on both client and server |
| Magic byte scanning | Server inspects the first 16 bytes of every upload for known executable signatures, regardless of declared extension |
| Content Security Policy | Blocks all inline scripts; `connect-src` restricted to `'self'` and `api.github.com` |
| CORS | `Access-Control-Allow-Origin` set to the exact request `Origin` only when it matches `https://<Host>`; wildcard never used |
| Security headers | `Strict-Transport-Security` (2 years, `includeSubDomains`, `preload`), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Permissions-Policy` (disables camera, microphone, geolocation, payment, USB, display-capture, clipboard, wake-lock, and sensors) |
| Input validation | Username, repo owner, repo name, branch, and folder validated with strict regex server-side before any GitHub API call |
| Filename sanitisation | Filenames validated against `/^[a-zA-Z0-9][a-zA-Z0-9._\-()\s]{0,253}$/`; path traversal characters rejected |

### Token Encryption Detail

Each user's GitHub personal access token is encrypted before being written to the registry repository:

1. A per-user encryption key is derived using **HKDF-SHA256** from the operator's `TOKEN_SECRET` and the username as the HKDF info parameter.
2. The token is encrypted with **AES-256-GCM** using a 12-byte random IV.
3. The ciphertext and IV are stored in the user's registry record. The plaintext token is never persisted.

---

## Rate Limiting

Rate-limit state is stored in a **Cloudflare KV** namespace (`RATE_LIMIT_KV`). Without the KV binding, a fallback in-memory `Map` is used; this resets on every Worker cold start and is not suitable for production.

| Limit | Window | Scope |
|---|---|---|
| 5 login attempts | 15 minutes | Per IP address |
| 10 login attempts | 15 minutes | Per username |
| 3 signup attempts | 15 minutes | Per IP address |

On exceeding the IP-based login limit, the server responds with HTTP `429`. KV entries are stored with a TTL matching the window expiry so records are cleaned up automatically.

---

## Blocked File Types

Extension blocklist (enforced client-side and server-side):

```
exe  bat  cmd  com  msi  ps1  psm1
sh   bash zsh  fish command
php  php3 php4 php5 php7 php8 phtml phar
asp  aspx cshtml jsp jspx
py   pyc  pyw  rb   pl   cgi  lua
js   mjs  cjs  ts   tsx  jsx
html htm  xhtml svg  xml
htaccess htpasswd
dll  so   dylib sys
vbs  vbe  wsf  wsh  hta
jar  war  ear  class
scr  pif  reg  lnk
app  dmg  pkg  deb  rpm  apk
```

In addition, the server inspects the **first 16 bytes** of every uploaded file for known executable magic byte sequences, regardless of the declared extension:

| Bytes (hex) | Format |
|---|---|
| `4D 5A` | Windows PE (MZ) |
| `7F 45 4C 46` | ELF binary |
| `FE ED FA CE` / `FE ED FA CF` / `CE FA ED FE` / `CF FA ED FE` | Mach-O (32/64-bit, big/little-endian) |
| `CA FE BA BE` | Java class file |
| `23 21` | Shell shebang (`#!`) |
| `3C 3F 70 68 70` | PHP opening tag (`<?php`) |
| `3C 73 63 72 69 70 74` | `<script` tag |
| `3C 68 74 6D 6C` / `3C 48 54 4D 4C` | HTML tag (lower/upper case) |

---

## File Size Limits

| Boundary | Value | Enforced by |
|---|---|---|
| Small-file threshold | 5 MB | Server (`SMALL_MAX_BYTES`) |
| Chunk size | 10 MB | Client + server (`CHUNK_SIZE`) |
| Chunked-upload trigger | 5 MB | Client (`CHUNK_THRESHOLD`) |
| Max base64 payload per chunk | ~14 MB (10 MB raw → ~13.4 MB Base64) | Server (`CHUNK_B64_MAX`) |
| Max chunk count | 512 | Server (`MAX_TOTAL_CHUNKS`) |
| Theoretical max file size | ~5 GB | 512 × 10 MB |
| GitHub Git Blobs hard cap | 100 MB | GitHub API |
| Cloudflare Pages Free request body | ~70 MB | Cloudflare |
| Cloudflare Pages Pro request body | ~95 MB | Cloudflare |

Practical maximum per upload on Cloudflare Pages Pro: **~95 MB**, constrained by Cloudflare's request body limit ahead of the GitHub 100 MB Git Blobs cap.

---

## API Reference

All endpoints are served under `/api/` by the Cloudflare Pages Function at `functions/api/[[path]].js`. Every response includes the security headers described in the [Security Model](#security-model) section. All request and response bodies are JSON unless otherwise noted.

### `GET /api/status`

Returns whether all required operator environment variables are present.

**Response**
```json
{ "ready": true }
```

---

### `POST /api/auth`

Authenticates a user and issues a session cookie.

**Request body**
```json
{ "username": "alice", "password": "..." }
```

**Responses**

| Status | Meaning |
|---|---|
| `200` | Authenticated; `Set-Cookie` header contains the encrypted session token |
| `401` | Invalid credentials |
| `429` | Rate limit exceeded |

---

### `GET /api/me`

Returns the current session's user metadata. Used to validate an existing session on page load.

**Response**
```json
{ "username": "alice", "display": "alice", "repo": "owner/repo-name" }
```

---

### `POST /api/logout`

Clears the session cookie server-side, invalidating the current session.

---

### `POST /api/signup`

Registers a new user account.

**Request body**
```json
{
  "username": "alice",
  "password": "...",
  "ghToken": "ghp_...",
  "ghOwner": "github-username",
  "ghRepo": "my-storage",
  "ghBranch": "main",
  "folder": "uploads"
}
```

**Responses**

| Status | Meaning |
|---|---|
| `200` | Account created |
| `409` | Username already taken |
| `400` | Validation error |
| `429` | Rate limit exceeded |

---

### `GET /api/files`

Lists all logical files in the current user's upload folder. Internal paths (`.chunks/`, `.manifests/`, `.storegit`) are excluded.

**Response**
```json
[
  { "name": "document.pdf", "size": 204800, "sha": "abc123...", "chunked": false },
  { "name": "large-video.mp4", "size": 52428800, "chunked": true }
]
```

---

### `POST /api/upload`

Uploads a single file ≤ 5 MB via the GitHub Contents API.

**Request body** — `multipart/form-data` with a `file` field.

---

### `POST /api/upload-chunk`

Uploads one part of a multi-chunk file.

**Request body** — `multipart/form-data`

| Field | Type | Description |
|---|---|---|
| `file` | binary | Raw chunk bytes (max 10 MB) |
| `name` | string | Original logical filename |
| `chunkIndex` | number | Zero-based part index |
| `totalChunks` | number | Total number of parts |
| `chunkSize` | number | Nominal chunk size in bytes |

---

### `POST /api/upload-finalize`

Called after all chunks have been uploaded. Writes the per-file manifest and updates `_index.json`.

**Request body**
```json
{
  "name": "large-video.mp4",
  "totalChunks": 5,
  "totalSize": 52428800,
  "blobs": ["sha1", "sha2", "sha3", "sha4", "sha5"]
}
```

---

### `GET /api/download?name={filename}`

Fetches a file by logical name and streams the bytes to the client. For chunked files, the Worker reassembles all parts before streaming. GitHub URLs are never forwarded to the client.

**Response** — raw file bytes with `Content-Type` and `Content-Length` headers set.

---

### `DELETE /api/delete`

Deletes a file and all associated storage.

**Request body — small file**
```json
{ "name": "document.pdf", "sha": "abc123..." }
```

**Request body — chunked file**
```json
{ "name": "large-video.mp4", "chunked": true }
```

Chunked deletion removes all part blobs, the per-file manifest, and the `_index.json` entry in a single commit.

---

## Operator Deployment

### Prerequisites

- A Cloudflare account with Pages enabled.
- A GitHub account to host the registry repository.

### Step 1 — Create the Registry Repository

Create a dedicated **private** GitHub repository to store user account records. This repository must be separate from any user storage repository.

### Step 2 — Generate a Registry Token

Generate a GitHub personal access token with the **`repo`** scope scoped to the registry repository. This token is stored as an environment variable and is never exposed to end users.

### Step 3 — Fork and Connect

1. Fork this repository to your GitHub account.
2. In the Cloudflare dashboard, go to **Workers & Pages → Create → Pages → Connect to Git** and connect the fork.

### Step 4 — Set Environment Variables

In the Cloudflare Pages project settings, add the following environment variables:

| Variable | Description |
|---|---|
| `TOKEN_SECRET` | Random 32-byte hex string — generate with `openssl rand -hex 32` |
| `REGISTRY_GITHUB_TOKEN` | GitHub PAT with `repo` scope for the registry repository |
| `REGISTRY_GITHUB_OWNER` | GitHub username or organisation that owns the registry repository |
| `REGISTRY_GITHUB_REPO` | Repository name of the registry |

### Step 5 — Bind a KV Namespace (Strongly Recommended)

1. In the Cloudflare dashboard, create a KV namespace under **Workers & Pages → KV → Create namespace**.
2. Bind it to the Pages project with the binding name **`RATE_LIMIT_KV`**.

Without this binding, rate-limit state is held in an in-memory `Map` that resets on every Worker cold start, rendering brute-force protection ineffective across separate requests.

### Step 6 — Deploy

Trigger a deployment from the Cloudflare Pages dashboard or by pushing to the connected branch. The service is available at the assigned `*.pages.dev` URL or any configured custom domain.

---

## User Registration

To register, a user must provide:

1. A username — 3–32 characters; letters, numbers, hyphens, and underscores only.
2. A password — minimum 8 characters.
3. A GitHub repository (private recommended) they own and have write access to.
4. A GitHub personal access token with the **`repo`** scope for that repository.

The server verifies repository access using the provided token before creating the account. The token is encrypted with AES-256-GCM (key derived via HKDF-SHA256 from `TOKEN_SECRET` and the username) before being written to the registry. The plaintext token is not retained after the signup request completes.

After registration, users authenticate using only their username and password. The GitHub token is decrypted server-side per request and is never transmitted to the client.

---

## Credits

Created by **Deb Guin** · [storegit.pages.dev](https://storegit.pages.dev)

---

## License

This project is licensed under the **MIT License**. See [LICENSE](LICENSE) for full terms.
