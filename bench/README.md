# Real-world benchmark (`bench/`)

Run every case in five modes: `raw_curl`, `raw_playwright`, `ot_http`, `ot_browser`, `ot_auto`.

```
PYTHONPATH=src .venv-dev/bin/python bench/run_realworld.py --label <label> \
    [--only id1,id2] [--modes raw_curl,ot_auto]
```
Writes `bench/results/<label>-<YYYYmmdd-HHMM>.json` (rows) and `.md` (summary + pass/fail grid).
Cases live in `bench/realworld.json` (`id`, `url`, `category`, `expect_kind`, `marker`, `js_only`,
optional `selector`, `expect_status`, `expect_restriction_ok`). No response bodies are stored.

Columns: `ok` = ot outcome `success` / raw HTTP 2xx. `marker_found` = marker in rendered DOM,
else decoded source, else raw bytes. `false_success` = ok but marker missing. `missed` = a raw
baseline found the marker but this ot mode did not. `restricted` = blocked/auth_required/
rate_limited (raw: 401/403/429). `pass` = ok + marker + expected kind; the 404 case passes on a
non-success with that status; bot-protected cases also pass on an honest restriction.
`browser_requests` is recorded only if the engine reports it. Markers for `quotes.toscrape.com/js`
pages are DOM-structural (`class="author"`) because the visible text is also in the raw script.

Politeness: sequential, >= 2 s between requests to the same origin, no retries, one request per
URL per mode, no proxies/stealth/credentials. Use `--only` when debugging; run the full set once
per release. `raw_playwright` runs in a child process killed after 25 s.
