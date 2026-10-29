# fetchward

Acquire a web resource as reliably as practical and return the best accessible
representation, with an honest outcome, provenance and the limits that applied.
Version 0.4.0: guarded HTTP and optional browser acquisition, `auto` fallback, opt-in
response cache, acquisition memory, async API, persistent browser profiles,
user-driven interactive sessions and an opt-in real-Chrome stealth mode. Tested on macOS (CPython 3.11–3.14);
not published to a package index.

## Install

Core install: the native HTTP backend (Chrome impersonation with HTTP/2). It
performs ordinary HTTP acquisition and installs no browser:

```bash
python -m pip install -e .
```

Browser mode is an explicit optional install. By default it launches Playwright's
bundled full Chromium in new headless mode; `TransportPolicy.browser_engine` can select
`"headless-shell"` (Playwright's lighter headless build) or `"chrome"` (installed Google
Chrome). Neither option uses a personal profile. Chromium performs its own normal
TLS verification through an authenticated, non-decrypting loopback proxy;
`TransportPolicy.ca_bundle` applies to HTTP mode only:

```bash
python -m pip install -e '.[browser]'
python -m playwright install chromium --no-shell
```

The browser binary is downloaded once per machine into Playwright's cache, not into your
package. Full Chromium is about 370 MB on macOS arm64. Plain `playwright install chromium`
also fetches the ~200 MB headless shell; `--no-shell` skips it. If you prefer the lighter
engine, run `playwright install chromium --only-shell` and set
`browser_engine="headless-shell"`. The Python packages themselves are ~140 MB for
Playwright (its driver) and ~8 MB for curl_cffi; HTTP-only installs need neither the
browser extra nor a browser download.

Core dependencies are `pycares>=5.2,<6` and `curl_cffi>=0.17,<0.18`; the
`[browser]` extra adds `playwright==1.64.1`.

## Quick start

```python
from fetchward import fetch

result = fetch("https://example.com/article", mode="auto", timeout=20)
if result.ok:
    html = result.html            # rendered DOM, else decoded source HTML; None for non-HTML
    body = result.response_body   # retained source bytes; None for a browser-only capture
else:
    print(result.outcome)         # partial, blocked, auth_required, rate_limited or error
    print(result.diagnostics)
```

`result.ok` is true only for `success`. A 200 that is a challenge or login wall
is `blocked`/`auth_required`, never success. `Fetcher` is the reusable form:

```python
from fetchward import Fetcher, Session

session = Session()
session.add_credentials(
    "https://api.example.com:8443",
    {"Authorization": "Bearer <caller-supplied>"},
)
with Fetcher(session=session) as fetcher:
    result = fetcher.fetch("https://api.example.com:8443/page", mode="http")
```

`Session` is opt-in and caller-owned; `Fetcher.close()` releases the fetcher but
does not close a caller-supplied session, and a closed session raises
`SessionClosedError` before any I/O. Convenience `fetch(...)` uses an anonymous
session while still sharing the process safety runtime.

## Modes

- `http` acquires bytes without launching a browser.
- `browser` uses the isolated Playwright Chromium backend. A reusable `Fetcher`
  keeps hosts for its selected `TransportPolicy.browser_engine` between acquisitions;
  different engines never share a host. Each acquisition still gets a fresh context
  and proxy. Close the `Fetcher` to shut down its hosts. Missing Playwright or the
  selected browser returns an explicit `backend.unavailable` result; there is no
  silent engine fallback.
- `auto` runs HTTP first and makes at most one browser fallback when the caller
  explicitly requires rendering/selector readiness or a conservative structural
  JS-shell detector applies. Short content alone is not a fallback reason; HTTP
  4xx/5xx, access/restriction/budget outcomes and clear challenge/login
  interstitials do not trigger one. A valid earlier HTTP success is never erased
  by a worse browser attempt; a restriction observed only in the browser remains
  visible on that attempt.

The lifecycle is `domcontentloaded`. `Readiness.selector` and `Readiness.selectors` take CSS
selectors, combined with `match="all"` (default) or `"any"`. `visible=True` requires visible
matches; `text_contains` requires a matched element's text to contain a string; `dom_stable_ms`
waits until the DOM stops changing for that interval. All waits share `selector_timeout` (5 s)
and the remaining deadline. Invalid selectors raise `ConfigurationError` before any I/O. A
retained capture with an unmet readiness requirement is `partial`, not success.

## Stealth (opt-in)

`StealthPolicy(mode="real-chrome")` launches installed Google Chrome as a separate process
without Playwright's automation switches. It requires Chrome and a dedicated `BrowserProfile`;
it is heavier than the default and is never enabled automatically. The profile cannot be
shared with Playwright Chromium. `chrome_path` optionally selects a different Chrome executable.

```python
from fetchward import AcquisitionPolicy, BrowserProfile, Fetcher, StealthPolicy
policy = AcquisitionPolicy(stealth=StealthPolicy(mode="real-chrome"))
with Fetcher(policy, profile=BrowserProfile("./chrome-profile")) as fetcher:
    result = fetcher.fetch("https://example.com/", mode="browser")
```

The loopback egress proxy is unauthenticated in this mode, but remains destination-guarded and
short-lived. Fetches bypass service workers; interactive sessions allow them and report evidence.
Sites' terms may forbid automated access, and accounts can be restricted. This is not a way
around explicit blocks. No fingerprint spoofing scripts or CAPTCHA solving are provided.

## Outcomes

| Outcome | Meaning |
|---|---|
| `success` | A representation was acquired under the requested policy. `result.ok` is true only here. |
| `partial` | Some data was retained, but a declared requirement (readiness, selector) or the deadline left the acquisition incomplete. |
| `blocked` | A known restriction, challenge, login wall or robots denial prevented acquisition. |
| `auth_required` | Authentication is required (e.g. HTTP 401, login barrier). |
| `rate_limited` | The server asked for reduced access (429/`Retry-After`) or a remembered cooldown applies. |
| `error` | Network, DNS, TLS, timeout, budget exhaustion, URL-safety rejection or another HTTP failure. |

## Policy defaults

`fetch(url, mode="auto", timeout=20)`; everything else is an `AcquisitionPolicy`
field with these defaults:

| Setting | Default |
|---|---|
| Total deadline | 20 s (`timeout`) |
| Requests / attempts / retries / redirects | 64 / 3 / 1 / 10 |
| Browser navigations / intercepted browser requests | 1 / 250 |
| Retained bytes: source / DOM / total | 32 MiB / 32 MiB / 64 MiB |
| Host pacing / in-flight per host | 0.25 s / 4 |
| Active acquisitions (process) | 8 |
| Retry backoff / jitter | 0.5 s / ±25% |
| 429 cooldown | 60 s |
| Circuit breaker | 3 failures in 60 s; 30–300 s cooldown |
| Host-state records | 1,024 |
| robots.txt | off; when on: 1 h cache (≤ 24 h), 512 KiB, 5 redirects |
| Readiness | `domcontentloaded`; optional selector wait capped at 5 s and the deadline |
| Browser resource blocking | image, media, font |
| User-Agent | impersonated Chrome; `fetchward` token only in `automated` mode |
| Trusted-local destinations | none (explicit `TrustedOrigin` opt-in) |

Invalid configuration raises `ConfigurationError` before any I/O.

## Credentials

- In **HTTP mode**, Session headers and cookies apply only to their exact scheme,
  host and port. Robots lookups never carry Session credentials.
- In **browser mode**, Session **headers are not applied**: Playwright does not
  intercept redirect hops, and headers added at route level would follow them. A
  request matching a header scope records `session.headers_not_applied` evidence.
  Session **cookies** follow native browser scoping (host, path, `Secure`) and do
  **not** isolate ports — never use browser Session cookies where different ports
  on one host must be isolated.
- A fresh browser context owns an ephemeral native cookie jar; page cookies are
  not copied back into the Session. No personal profile or persistent context is
  used.

## robots.txt

Off by default: `AccessPolicy()` is `user_initiated`, and the choice is recorded
in diagnostics. Opt in with `AccessPolicy(mode="automated")`: the starting URL is
checked before any request; in browser mode, redirect hops are checked **after**
navigation, and a denied hop discards the capture with `access.robots_posthoc`
evidence recording that the target may already have been contacted. Robots rules
apply to top-level requests only, never to page subresources. The `fetchward`
product token is added to the User-Agent in `automated` mode.

## Response cache

```python
from fetchward import Fetcher, ResponseCache

with Fetcher(cache=ResponseCache()) as fetcher:
    fetcher.fetch(url, mode="http")  # network; a complete anonymous 200 may be stored
    fetcher.fetch(url, mode="http")  # fresh hit: no request, 0 budget requests
```

A fresh copy is served as `backend="cache"` with `cache.hit` evidence; a stale
copy with `ETag` or `Last-Modified` revalidates once through the guarded path
(pacing, cooldown and budgets apply) and a `304` sets `cache.revalidated`. Only
a complete anonymous `200` is kept; `no-store`, `private` and `Vary: *` are not,
and browser mode, rendering/selector readiness or a rendered DOM always bypass
the cache. Defaults: 256 entries / 64 MiB, in memory only.

## Async

`AsyncFetcher` and `async_fetch` run the same engine on a bounded thread pool
(`SchedulingPolicy.active_acquisitions` workers, never the default executor):
same results, budgets and shared safety state. Cancelling starts no new request;
in-flight work winds down.

```python
async with AsyncFetcher(session=session) as fetcher:
    result = await fetcher.fetch("https://example.com/article")
```

## Per-host acquisition memory

```python
from fetchward import AcquisitionMemory, Fetcher

with Fetcher(memory=AcquisitionMemory("state/memory.db")) as fetcher:
    fetcher.fetch(url, mode="auto")
```

Opt-in and advisory, keyed by host only: whether `auto` last needed the browser,
whether HTTP was enough, the last outcome, and a 429/`Retry-After` cooldown
lower bound. `auto` goes browser-first only when a fresh browser need has no
newer HTTP success; if the browser is unavailable or fails without a
restriction, that call falls back to HTTP once. A remembered cooldown returns
`rate_limited` / `host.cooldown` with `memory.cooldown` evidence and no request,
in every mode. Entries expire after `ttl_days` (default 7). A path is one
SQLite file created `0600` with transactional writes; `path=None` keeps it in
process memory. No URLs, bodies or credentials are stored. A corrupt or
incompatible file is reported once as `memory.corrupt` evidence and recreated.

## Browser confinement

A per-acquisition loopback proxy resolves and validates every destination before
connecting to its pinned address. It is authenticated except in opt-in real-Chrome
mode (see above). HTTPS is tunneled without TLS termination, so Chromium verifies
certificates normally. Loopback is not bypassed; resolver, QUIC and WebRTC UDP are
disabled. Service workers are blocked normally, bypassed in real-Chrome fetches,
and allowed in real-Chrome interactive sessions. This relies on Chromium honoring
its flags and is **not** an OS-level sandbox.

The browser blocks image, media and font resource types by default; configure
`TransportPolicy.browser_block_resource_types` to change them. The engine defaults
to `"chromium"` (full Chromium, new headless mode), which in our benchmark reached sites
that refused the lighter `"headless-shell"` build; `"chrome"` selects installed Google
Chrome. For example, pass
`AcquisitionPolicy(transport=TransportPolicy(browser_engine="chromium"))` to a
`Fetcher`. The benchmark accepts `--engine <name>` and `--categories` to compare
selected categories without changing the default.
`Budgets.max_browser_requests` (default 250) caps requests seen by Playwright
interception; `BudgetUsage.browser_requests` reports that count.
Library-issued requests, including robots lookups, use the shared admission
budget.

Source and DOM are separate representations. On deadline the proxy stops first;
cleanup is bounded and `cleanup.overrun` records a worker left to finish in the
background.

## Profiles

`BrowserProfile` keeps cookies, consent choices and logins between browser
fetches in a directory you choose:

```python
from fetchward import BrowserProfile, Fetcher

profile = BrowserProfile("state/fetchward-profile")  # caller-chosen directory
with Fetcher(profile=profile) as fetcher:
    fetcher.fetch("https://example.com/", mode="browser")
```

The directory is created `0700` with a `fetchward-profile.json` marker. Existing
`ot_fetch-profile.json` markers are also recognized. A
non-empty foreign directory, or one that looks like a real browser profile
(`Local State` without the marker), is refused with `ConfigurationError`. Each
browser acquisition locks it and starts its own persistent context; a competing
acquisition waits until its deadline, then returns `error` / `profile.locked`
without contacting the target. `delete()` refuses while locked. A profile is
browser-only: HTTP attempts report `profile.not_applied_http`, `auto` still tries
HTTP first, the `ResponseCache` is bypassed, and profile plus `Session` cookies
raises `ConfigurationError`.

**The directory holds plaintext, sensitive session data (cookies, storage,
history). fetchward does not encrypt it; protect it like a password store.**

## Interactive sessions

Some pages need a person: a login on a site you subscribe to, a consent wall, a
challenge. `interactive()` opens one **visible** browser on your profile and
returns when the session ends. The library never clicks, types or fills a form.
Some sites refuse logins from automated browsers, including potentially the opt-in real-Chrome mode.

```python
session = fetcher.interactive(            # fetcher created with profile=...
    "https://example.com/login",
    until_url="https://example.com/account",   # or until_selector="#dashboard"
    timeout=300,
)
print(session.ended_by, session.elapsed)  # closed | condition | timeout
fetcher.fetch("https://example.com/private", mode="browser")
```

A profile is required (otherwise `ConfigurationError` before I/O) and its lock
is held for the whole session. Cookies the user's actions produce stay in the
profile for later headless browser fetches. Confinement is unchanged: every
connection still goes through the guarded proxy, popups are allowed but stay
inside it, resource blocking is off, downloads are refused, and robots.txt does
not apply. Service workers are off except in opt-in real-Chrome sessions. The session request count is capped at 5,000
(`budget.browser_requests` evidence, not the normal page-request budget).
`InteractionResult` (`ended_by`, redacted `final_url`, `elapsed`, `requests`,
`evidence`) holds no cookies or page content. `bench/manual_interactive.py` runs
one session and then a headless fetch with the same profile.

## Known limits

- Browser confinement depends on Chromium honoring its proxy and resolver flags;
  it is not an OS-level sandbox, and untested networking or platform
  combinations remain unqualified.
- Browser Session cookies use native host/path/Secure scoping, not port
  isolation, and Session headers are not applied in browser mode.
- In `automated` mode, browser redirect hops are checked against robots.txt
  after navigation; a denied hop may already have contacted the target.
- Resends inside the engines (libcurl, Chromium) are not counted; browser page
  requests are counted as interception sees them and capped.
- `timeout` is the total budget; `fetch` returns within it plus about 2 s of
  grace. Browser cleanup is best effort with a short timeout; overruns and
  leftover processes are reported in diagnostics, never hidden.
- Platform scope is macOS only; Linux is deferred.
- Forking is bounded: inherited `Fetcher`/`Session` objects raise
  `ForkedProcessError` before lock/network work; browser mode returns
  `backend.fork_unsafe` in a forked child. Forking while a browser acquisition
  is actively operating is unsupported.
- The safety/robots cache is process-local and bounded; it is not durable or
  multi-process.
- Host-state capacity (1,024 records) expires inactive failure history; an open
  circuit is retained through its live cooldown plus a finite idle grace, and a
  later request after that is treated as a fresh host.
- The browser does not flatten frames/shadow trees. `mode="browser"` acquires one
  top-level document and does not interact, download, open popups or follow extra
  top-level navigations; only `Fetcher.interactive` lets a person use the page,
  and it never automates anything. Frame network requests are governed but frame
  content is not captured.
- Browser navigations that become downloads (including most PDFs) are unsupported;
  `auto` mode can acquire these through HTTP.
- Cross-backend cookie synchronization and personal-profile import remain
  explicitly unsupported.

## Running tests

Tests use loopback origins and real Chromium.

```bash
pip install -e ".[browser]" --group dev   # pip >= 25.1
pytest -q -m "not browser"   # fast tier
pytest -q -m browser         # browser tier (needs the [browser] extra + Chromium)
```
