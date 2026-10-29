# fetchward Changelog

## 0.4.0 — 2026-10-29

Adds an opt-in stealth mode for sites that refuse automated browsers. Verified: 481 tests on CPython 3.11–3.14 (macOS arm64).

- New opt-in `StealthPolicy(mode="real-chrome")` (`AcquisitionPolicy.stealth`): profile-backed fetches and interactive sessions run the installed Google Chrome as an ordinary process, without Playwright's automation switches, so `navigator.webdriver` is false. It requires a `BrowserProfile` (`ConfigurationError` otherwise) and is never enabled automatically.
- In this mode the loopback egress proxy is unauthenticated for the lifetime of the Chrome process, but every destination is still guarded; results carry `stealth.real_chrome` (Chrome version) and `stealth.proxy_unauthenticated` evidence. Fetches bypass service workers; interactive sessions allow them (`stealth.service_workers_allowed`).
- Profiles record which browser engine uses them (marker schema 2; schema-1 markers are still read); using a profile with the other engine raises `ConfigurationError`.
- `bench/manual_interactive.py` accepts `--stealth real-chrome`.

## 0.3.0 — 2026-10-28

Adds persistent browser profiles, user-driven interactive sessions and a browser engine choice, and renames the package to `fetchward`. Verified: 475 tests on CPython 3.11–3.14 (macOS arm64); real-world benchmark with zero false successes.

- AWS WAF challenge interstitials served with 2xx are now detected and reported as `blocked`; diagnostics report the challenge check as an observation instead of a not-performed placeholder.
- Browser mode never reports a Chromium built-in viewer page (e.g. the PDF viewer) as the requested non-HTML resource; it stops with `backend.unsupported` and `browser.viewer_substituted` evidence, while `auto` still retrieves the document over HTTP.
- Renamed the distribution and import package to `fetchward`; new profiles use fetchward marker/lock names while existing `ot_fetch-profile.json` markers remain readable.

- The default browser engine is now full Chromium in new headless mode (`browser_engine="chromium"`); `"headless-shell"` remains available. Install with `playwright install chromium --no-shell`.
- Hitting `Budgets.max_browser_requests` is reported as evidence and in `budget.exhausted` but no longer makes a rendered page `partial` by itself.

- New `BrowserProfile`: a caller-chosen directory (`0700`, `fetchward-profile.json` marker) that persists cookies, consent choices and logins between browser fetches, locked per acquisition (`profile.locked` when another acquisition holds it). Profiles hold plaintext session data, apply to browser attempts only (HTTP attempts record `profile.not_applied_http`), bypass `ResponseCache`, and cannot be combined with `Session` cookies.
- `Fetcher` and `AsyncFetcher` accept `profile=BrowserProfile(...)`; profile-backed acquisitions launch their own persistent Chromium context per acquisition instead of using the reused pool.
- Added `TransportPolicy.browser_engine` (`chromium`, `headless-shell`, or `chrome`) and engine-specific browser host pools; the real-world benchmark accepts `--engine` and `--categories`.
- New `Fetcher.interactive(url, *, until_url=None, until_selector=None, timeout=300)`: an explicit user-mediated session in a visible Chromium on the profile (same proxy hardening, popups allowed but confined, resource blocking off, downloads off, robots not consulted, 5,000-request session cap), ending on window/page close, an `until_url` prefix or attached `until_selector`, or the timeout; returns an exported `InteractionResult` (`ended_by`, redacted `final_url`, `elapsed`, `requests`, `evidence`) and leaves the cookies in the profile for later browser fetches. It requires a profile, never automates the page, and refuses `Session` cookies.
- Profile-backed browser launches probe Chromium's native User-Agent at most once per process and engine binary instead of at every launch.

## 0.2.0 — 2026-10-28

First release after the reset. Includes
the v0.1 scope (HTTP, browser, `auto`, outcomes, safety) and the v0.2 additions (cache,
memory, async, richer readiness, browser reuse). Verified: 453 tests on CPython
3.11–3.14 (macOS 26.4.1 arm64); real-world benchmark `bench/results/v0.2-rc-20261028-1601.md`
with zero false successes.


- Browser mode retains complete non-HTML top-level responses as source, without a rendered DOM; navigation downloads remain unsupported.
- Reusable Fetchers pool Chromium hosts, with a fresh isolated context and egress proxy per browser acquisition; closing a Fetcher shuts down its hosts.

- HTTP and browser responses with final status 202 are reported as partial, with an evidence-backed browser fallback in auto mode.

- Browser readiness now supports multiple selectors, all/any matching, visibility and text conditions, plus bounded DOM-stability waits.
- Browser mode now uses Chromium's native TLS and cookies through an authenticated non-decrypting egress proxy instead of TLS interception or an OS sandbox.
- Browser page requests are capped by `Budgets.max_browser_requests` (default 250), reported as `BudgetUsage.browser_requests`; `TransportPolicy.browser_block_resource_types` configures the default image/media/font blocking.
- Browser Session cookies use native host/path/Secure scope, not port isolation (native browser scope); Session headers are not applied and matching scopes report `session.headers_not_applied` (redirect-safe credential handling).
- Automated browser redirect robots decisions are checked post-hoc and denied captures are discarded with `access.robots_posthoc` evidence (post-navigation checking).

- robots.txt is now opt-in: `AccessPolicy()` defaults to `user_initiated`; use `AccessPolicy(mode="automated")` to apply robots.txt (opt-in policy).
- HTTP mode now impersonates Chrome (`chrome152`) with the matching TLS and HTTP/2 fingerprints instead of forcing HTTP/1.1 with no reuse.
- The default HTTP `User-Agent` is the impersonated Chrome UA with no `fetchward` token; `TransportPolicy.user_agent` is sent as given, and `AccessPolicy(mode="automated")` still appends the product token.
- The curl_cffi dependency pin is relaxed to `curl_cffi>=0.17,<0.18`; an exact audited-pair match is no longer required, and only a missing package stops with `backend.unavailable`.
- New opt-in `ResponseCache`: anonymous HTTP GETs can be answered from a fresh in-memory copy (evidence `cache.hit`, zero budget requests), and a stale copy with `ETag`/`Last-Modified` is revalidated with one conditional request (evidence `cache.revalidated`).
- New async API: `AsyncFetcher` and `async_fetch` run the same synchronous engine on a bounded thread pool (one worker per active acquisition) with cooperative cancellation; results, outcomes, budgets and process-shared safety state are identical to the sync API.
- New opt-in `AcquisitionMemory` (`Fetcher(memory=...)`): remembers per host whether `auto` needed the browser, whether HTTP was enough, the last outcome and a 429/`Retry-After` cooldown, optionally in a `0600` SQLite file; `auto` then goes browser-first for known browser hosts, and a remembered cooldown answers `rate_limited` without a request in every mode.
- README rewritten for clarity: quick start, modes, outcomes, policy defaults, credentials, robots, cache/async/memory, browser confinement and known limits; stale references to the archived plan documents removed from the README and source docstrings.
- Benchmark scorer (`bench/run_realworld.py`): `fetchward_http` on a selector case records `n/a` (excluded from counts) instead of a failure, a `suspect_success` column flags bot-protected cases that report `ok` without the marker, and result filenames no longer truncate dotted labels.
- Removed `tests/harness/h1origin.py`, which no test imports.
