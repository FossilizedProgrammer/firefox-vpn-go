**English** | [فارسی](README.md) | [Русский](README.ru.md)

# ffvpn — Go client for Firefox's built-in VPN

`ffvpn` is a standalone Go client for **IP Protection** (Firefox's built-in VPN,
based on Mozilla VPN). It signs in to the Guardian service with your Firefox
Account, obtains short-lived "ProxyPass" tokens, and exposes the same proxy
edge Firefox uses as a **local SOCKS5 / HTTP CONNECT proxy** for any
application.

> ⚠️ **Server-side prerequisite (not bypassable):** Guardian only serves
> accounts that have a Mozilla VPN subscription (`403` otherwise) and are in an
> allowed region (`451` for disallowed regions). These checks are entirely
> server-side; this client only makes the same requests Firefox itself makes.
> Using an unofficial client may violate the Mozilla VPN Terms of Use and
> carries a risk of account throttling or suspension.

## Architecture (derived from Firefox 157 source)

```
Your app ──► local SOCKS5/HTTP proxy (127.0.0.1)
                │
                ▼
        TLS + HTTP CONNECT with header
        Proxy-Authorization: Bearer <JWT>     ──►  *.m1.fastly-masque.net:2499
                │
                ▼
            Internet (egress from the selected country)
```

- **Server list**: a public Remote Settings collection named `vpn-serverlist`
  (no authentication).
- **Authentication**: the Firefox Account `sessionToken` → an OAuth token with
  the `profile` and `https://identity.mozilla.com/apps/vpn` scopes (the same
  desktop Firefox client_id: `5882386c6d801776`) → the Guardian APIs on
  `https://vpn.mozilla.org` (the actual Firefox pref value; the `.com` domain
  in the JS fallback never resolves at all):
  - `POST /api/v1/fpn/activate` — activation and entitlement retrieval
  - `GET  /api/v1/fpn/token` — retrieve a short-lived JWT (rotated 2 minutes
    before expiry)
  - `X-Quota-*` headers — bandwidth usage
- **Tunnel**: current records register no `protocols`, so per Firefox's own
  `IPPChannelFilter.sys.mjs` logic the default protocol is CONNECT over TLS
  and the hostname is resolved by the edge (equivalent to
  `TRANSPARENT_PROXY_RESOLVES_HOST`).

## Build

Requirement: [Go](https://go.dev) 1.24+ (the client is pure Go with no CGO;
nothing beyond Go itself is required).

Build natively on the target OS:

```sh
# Linux
go build -o ffvpn .

# Windows (PowerShell or cmd)
go build -o ffvpn.exe .
```

Cross-compile from Linux — since there are no platform dependencies and no
CGO, it works with no extra setup:

```sh
GOOS=linux   GOARCH=amd64 go build -o ffvpn .               # Linux x86-64
GOOS=windows GOARCH=amd64 go build -o ffvpn.exe .           # Windows x86-64
GOOS=windows GOARCH=arm64 go build -o ffvpn-arm64.exe .     # Windows on ARM
GOOS=darwin  GOARCH=arm64 go build -o ffvpn-macos .         # Mac (Apple Silicon)
```

## Platforms (Windows and Mac)

Since profile mode was removed, this client contains no OS-specific code at
all; behavior on Windows and Mac is exactly the same (build commands are in
the "Build" section). Practical differences on Windows:

- `signedInUser.json` path:
  `%APPDATA%\Mozilla\Firefox\Profiles\<profile>\signedInUser.json`
  (on Mac: `~/Library/Application Support/Firefox/Profiles/<profile>/`).
  Extracting the token in PowerShell, no jq needed:

  ```powershell
  (Get-Content "$env:APPDATA\Mozilla\Firefox\Profiles\xxxx.default-release\signedInUser.json" |
    ConvertFrom-Json).accountData.sessionToken
  ```

- Stop the program with Ctrl+C (`SIGTERM` does not exist on Windows).
- Listening on `127.0.0.1` usually does not trigger Windows Firewall; but if
  you listen on all interfaces with `--socks 0.0.0.0:PORT`, you will likely
  see a firewall prompt once.


## Running

The only authentication method is passing the Firefox Account `sessionToken` —
a 64-character hex string that Firefox stores in plain text in the active
profile's `signedInUser.json` (the `accountData.sessionToken` field). Extract
it:

```sh
jq -r '.accountData.sessionToken' ~/.mozilla/firefox/xxxxxxxx.default-release/signedInUser.json
```

and pass it to the program:

```sh
./ffvpn --session-token <64 hex>
```

The default listening port is `127.0.0.1:1080`; to change it:

```sh
./ffvpn --session-token <64 hex> --socks 127.0.0.1:2080
```

Or a HTTP CONNECT proxy instead of SOCKS5 — passing `--http` alone disables
the SOCKS default (passing both = both):

```sh
./ffvpn --session-token <64 hex> --http 127.0.0.1:9088
```

Without `--session-token` (and unless `--email` is given) the program refuses
to start.

> ⚠️ **Email/password login (`--email`) usually does not work**: the
> api.accounts.firefox.com edge blocks `/account/login` requests from
> non-browser clients with HTTP 406 (confirmed with live testing; with any
> User-Agent, including curl and PyFxA). If you see `fxa: HTTP 406` you have
> hit this filter; use `--session-token`. The rest of the chain
> (session/status, OAuth, Guardian) works fine from Go.

Successful output should look something like:

```
FxA session OK (uid 6b2f21a9...)
Entitlement: subscribed=true uid=123 maxBytes=... limitedBandwidth=true
Using proxy edge: faor73.m1.fastly-masque.net:2499
Proxy pass valid until 2026-10-06T18:44:12Z
SOCKS5 proxy listening on 127.0.0.1:1080
```

Then point any application at `socks5://127.0.0.1:1080` (curl, for example):

```sh
curl --socks5-hostname 127.0.0.1:1080 https://ifconfig.me
```

> 💡 The path to the active Firefox profile directory (to find
> `signedInUser.json` and extract the token) can be seen in
> `about:profiles` (the root of the "Default Profile"). If you are not signed
> in, sign in to your account in Firefox first so that `signedInUser.json`
> gets created.

### Viewing quota usage (without running the proxy)

To just see how much of the bandwidth quota has been used — without bringing
up the local proxy:

```sh
./ffvpn --usage --session-token <64 hex>
```

Output:

```
FxA session OK (uid 6b2f21a9...)
Entitlement: subscribed=true uid=123 maxBytes=... limitedBandwidth=true
Bandwidth: 1.8 GiB of 10.0 GiB used (18%), 8.2 GiB left resets 2026-11-01
```

This data comes from the `X-Quota-*` headers of the Guardian response (the
same headers Firefox itself reads); the "resets" date is when the monthly
quota resets.

### Listing exit countries

The server list comes from a public Remote Settings collection; no token or
authentication is needed to see the available countries:

```sh
./ffvpn --list-countries
```

Only countries without the premium lock (the ones Firefox shows to free
users):

```sh
./ffvpn --list-countries --free-only
```

Output:

```
Available exit countries (select with --country CODE):
  US   United States        4 servers, 2 cities
  CA   Canada               2 servers, 1 city
```

Then select the exit country with `--country CODE` (default: the server-side
anycast suggestion). The server count only includes non-quarantined servers; a
country showing "0 servers" cannot be selected, and if you pass an invalid
code the error message lists the allowed codes.

About the `(locked)` flag: this field comes from the server list data itself
and is described in the Firefox source as "this country is locked behind a set
of preconditions." The Firefox panel only shows locked countries to premium
users — premium means having a Mozilla VPN subscription, or unlimited
bandwidth, or Firefox being the system default browser — and hides these
countries from the selection list for everyone else. Firefox's own proxy core
(`getLocation`) does not check this flag when selecting a server; ffvpn only
displays it and blocks nothing client-side — the edge has the final say.

### Key flags

| Flag | Description |
|---|---|
| `--session-token HEX` | FxA session token — from the Firefox profile's `signedInUser.json` (see above) |
| `--email` / `--password` | Interactive login — usually hits the 406 edge filter (see above) |
| `--socks HOST:PORT` | Local SOCKS5 proxy address (default `127.0.0.1:1080`; empty string = disabled) |
| `--http HOST:PORT` | Local HTTP CONNECT proxy (default disabled; passing it alone disables the SOCKS default) |
| `--usage` | Just show quota usage and exit; the local proxy does not start |
| `--country XX` | Select the exit country (default: server-side anycast suggestion; list: `--list-countries`) |
| `--server HOST:PORT` | Bypass the server list and connect to a specific edge |
| `--dial-proxy socks5://[user:pass@]H:P` | Reach the edge through another SOCKS5 proxy (bootstrap proxy; optional RFC 1929 user/pass) |
| `--sni NAME` | SNI name sent in the ClientHello to the edge (default: the edge's domain name). The edge certificate is still validated against the edge's real name, not NAME |
| `--guardian URL` | Override the Guardian server (for testing) |
| `--list-countries` | Just show exit countries and exit; no authentication needed |
| `--free-only` | With `--list-countries`: hide premium-locked countries |
| `--verbose` | Verbose logging |

## Security notes

- The `sessionToken` is equivalent to an "account key": anyone who has it can
  obtain OAuth tokens in your name. Never send it anywhere, and after use you
  can reset sessions by signing out/in in Firefox.
- Your traffic passes through the Fastly/Mozilla edge; like Firefox itself,
  the destination (hostname) is visible to the edge in the CONNECT request,
  but your local ISP only sees a TLS connection to `*.fastly-masque.net`.

## Tests

```sh
go test ./...                                   # full suite with mock servers
FFVPN_LIVE_TEST=1 go test -run TestLiveFetch -v ./internal/servers/   # live server list fetch
```

Test coverage:

- FxA crypto (quickStretch v1/v2, authPW, Bearer session derivation) against
  independently generated vectors (Python) plus RFC 5869 and RFC 7914 vectors
- The full OAuth flow (PKCE) and login/TOTP against a mock FxA server
- The Guardian client (activate/token/401/403/429/451 errors and quota headers)
- Server list parsing (default connect, quarantine, explicit protocol) + a
  live test
- The tunnel (TLS + CONNECT + Bearer) and local proxies + token rotation in an
  end-to-end test of the whole binary + `--usage` mode

What cannot be tested here: real FxA/Guardian responses with a premium
account (subscription/region). The logic of both is taken exactly from the
Firefox source.

## Code layout

```
main.go                     wiring everything together, token rotation, flags
internal/fxa/               FxA login (v1/v2), TOTP, key derivation, OAuth/PKCE
internal/guardian/          Guardian client and ProxyPass/Usage
internal/servers/           server list from Remote Settings
internal/tunnel/            TLS + CONNECT with Bearer; optional socks5 dialer
internal/localproxy/        local SOCKS5 (RFC 1928) and HTTP CONNECT servers
```

Implementation reference: the `toolkit/components/ipprotection/` modules in
the Firefox source and the reference PyFxA library (the Bearer flow without
Hawk per ADR-0022).
