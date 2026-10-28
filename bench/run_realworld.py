"""Real-world acquisition benchmark: raw baselines vs fetchward http/browser/auto.

Sequential, >= 2 s between requests to the same origin, no retries, one request per URL per
mode. No proxies, stealth or credentials. Response bodies are never stored.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import statistics
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

ALL_MODES = ("raw_curl", "raw_playwright", "ot_http", "ot_browser", "ot_auto")
OT_RESTRICTIONS = {"blocked", "auth_required", "rate_limited"}
RAW_RESTRICTION_STATUS = {401, 403, 429}
MIN_ORIGIN_GAP = 2.0
PW_GUARD = 25.0

_last_hit: dict[str, float] = {}


def _pace(url: str) -> None:
    origin = urlsplit(url).netloc
    wait = _last_hit.get(origin, 0.0) + MIN_ORIGIN_GAP - time.monotonic()
    if wait > 0:
        time.sleep(wait)


def _touch(url: str) -> None:
    _last_hit[urlsplit(url).netloc] = time.monotonic()


def _kind_from_media(media: str | None) -> str:
    media = (media or "").split(";")[0].strip().lower()
    if media in ("text/html", "application/xhtml+xml"):
        return "html"
    if media == "application/json" or media.endswith("+json"):
        return "json"
    return "file"


def _found(marker: str, body: bytes, text: str | None) -> bool:
    if text is not None and marker in text:
        return True
    return marker.encode() in body


# --- raw baselines -------------------------------------------------------------------------


def run_raw_curl(case: dict) -> dict:
    from curl_cffi import requests

    resp = requests.get(case["url"], impersonate="chrome", timeout=20)
    body = resp.content
    try:
        text = resp.text
    except Exception:
        text = None
    return {
        "status": resp.status_code,
        "kind": _kind_from_media(resp.headers.get("content-type")),
        "final_url": str(resp.url),
        "bytes": len(body),
        "marker_found": _found(case["marker"], body, text),
    }


def _pw_child(url: str, selector: str | None, marker: str) -> None:
    from playwright.sync_api import TimeoutError as PWTimeout
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        try:
            page = browser.new_page()
            resp = page.goto(url, wait_until="domcontentloaded", timeout=20000)
            if selector:
                try:
                    page.wait_for_selector(selector, timeout=5000)
                except PWTimeout:
                    pass
            content = page.content()
            media = resp.headers.get("content-type") if resp else None
            out = {
                "status": resp.status if resp else None,
                "kind": _kind_from_media(media),
                "final_url": page.url,
                "bytes": len(content.encode()),
                "marker_found": marker in content,
            }
        finally:
            browser.close()
    print("RESULT " + json.dumps(out))


def run_raw_playwright(case: dict) -> dict:
    cmd = [sys.executable, __file__, "--_pw-child", case["url"], case.get("selector") or "",
           case["marker"]]
    env = dict(os.environ, PYTHONPATH=str(ROOT / "src"))
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                            env=env, start_new_session=True)
    try:
        stdout, stderr = proc.communicate(timeout=PW_GUARD)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
        proc.communicate()
        raise TimeoutError("playwright guard 25s")
    for line in stdout.splitlines():
        if line.startswith("RESULT "):
            return json.loads(line[7:])
    last = (stderr.strip().splitlines() or ["no output"])[-1]
    raise RuntimeError(last[:200])


# --- fetchward ------------------------------------------------------------------------------


def run_ot(case: dict, mode: str, engine: str) -> dict:
    from fetchward import AccessPolicy, AcquisitionPolicy, Fetcher, Mode, Readiness, TransportPolicy

    selector = case.get("selector")
    readiness = Readiness(selector=selector, selector_timeout=5.0) if selector else Readiness()
    policy = AcquisitionPolicy(
        readiness=readiness, access=AccessPolicy(mode="user_initiated"),
        transport=TransportPolicy(browser_engine=engine),
    )
    fetcher = Fetcher(policy)
    try:
        result = fetcher.fetch(case["url"], mode=mode, timeout=20)
    finally:
        fetcher.close()
    sel = result.selected
    source = sel.source if sel is not None else None
    rendered = sel.rendered if sel is not None else None
    found = False
    if rendered is not None and case["marker"] in rendered.dom:
        found = True
    elif source is not None:
        found = _found(case["marker"], source.body, source.decoded_text)
    budget = result.diagnostics.budget
    reasons = list(sel.reasons) if sel is not None and sel.reasons else [
        r for a in result.attempts for r in a.reasons
    ]
    nbytes = len(source.body) if source is not None else 0
    if rendered is not None:
        nbytes = max(nbytes, len(rendered.dom.encode()))
    return {
        "outcome": result.outcome.value,
        "status": source.status_code if source is not None else None,
        "kind": source.kind.value if source is not None else None,
        "final_url": sel.final_url if sel is not None else None,
        "bytes": nbytes,
        "marker_found": found,
        "budget_requests": budget.requests,
        "browser_requests": getattr(budget, "browser_requests", None),
        "browser_attempt": any(a.mode is Mode.BROWSER for a in result.attempts),
        "reasons": reasons[:3],
    }


# --- driver --------------------------------------------------------------------------------


def run_row(case: dict, mode: str, engine: str = "chromium") -> dict:
    from fetchward import ConfigurationError

    row = {"case": case["id"], "category": case["category"], "mode": mode, "url": case["url"],
           "engine": engine if mode.startswith("ot_") else None,
           "expect_kind": case["expect_kind"], "js_only": case["js_only"]}
    _pace(case["url"])
    started = time.monotonic()
    data = None
    try:
        if mode == "raw_curl":
            data = run_raw_curl(case)
        elif mode == "raw_playwright":
            data = run_raw_playwright(case)
        else:
            data = run_ot(case, mode.removeprefix("ot_"), engine)
    except ConfigurationError as exc:
        # e.g. ot_http on a selector case: rendering is required, so the mode cannot apply.
        data = {"outcome": "n/a", "error": str(exc)[:160], "marker_found": False}
    except Exception as exc:  # recorded, never retried
        data = {"outcome": "error", "error": f"{type(exc).__name__}: {str(exc)[:160]}",
                "marker_found": False}
    finally:
        if data is None or data.get("outcome") != "n/a":
            _touch(case["url"])  # no request left the process for n/a; don't pace the next one
    elapsed = round(time.monotonic() - started, 2)
    if mode.startswith("raw_") and "outcome" not in data:
        st = data.get("status")
        data["outcome"] = f"http_{st}" if st is not None else "error"
        data["ok"] = st is not None and 200 <= st < 300
    else:
        data["ok"] = data.get("outcome") == "success"
    row.update(data)
    row["elapsed"] = elapsed
    row["restricted"] = (
        row["outcome"] in OT_RESTRICTIONS or row.get("status") in RAW_RESTRICTION_STATUS
    )
    row["false_success"] = bool(row["ok"] and not row["marker_found"])
    row["suspect_success"] = bool(
        row["ok"] and not row["marker_found"] and row["category"] == "bot_protected"
    )
    row["pass"] = _passes(case, row)
    return row


def _passes(case: dict, row: dict) -> bool:
    if case.get("expect_status"):
        return (not row["ok"]) and row.get("status") == case["expect_status"]
    if row["ok"] and row["marker_found"] and row.get("kind") == case["expect_kind"]:
        return True
    return bool(case.get("expect_restriction_ok") and row["restricted"])


def _mark_missed(rows: list[dict]) -> None:
    by_case: dict[str, list[dict]] = {}
    for r in rows:
        by_case.setdefault(r["case"], []).append(r)
    for group in by_case.values():
        raw_hit = any(r["mode"].startswith("raw_") and r["marker_found"] for r in group)
        for r in group:
            r["missed"] = bool(r["mode"].startswith("ot_") and raw_hit and not r["marker_found"])


def _pct(vals: list[float], q: float) -> float:
    s = sorted(vals)
    return s[min(len(s) - 1, int(round(q * (len(s) - 1))))] if s else 0.0


def summarize(rows: list[dict], modes: list[str], label: str) -> str:
    out = [f"# Real-world benchmark: {label}", "",
           "| mode | cases | n/a | marker found | ok | false success | suspect success | missed "
           "| honest restriction | median s | p95 s | requests | browser launches |",
           "|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for m in modes:
        all_g = [r for r in rows if r["mode"] == m]
        g = [r for r in all_g if r["outcome"] != "n/a"]  # n/a rows made no request; excluded
        if not all_g:
            continue
        el = [r["elapsed"] for r in g]
        reqs = sum(r.get("budget_requests", 0) or 0 for r in g) if m.startswith("ot_") else "-"
        if m == "raw_playwright":
            launches = len(g)
        elif m.startswith("ot_"):
            launches = sum(1 for r in g if r.get("browser_attempt"))
        else:
            launches = 0
        out.append(
            f"| {m} | {len(g)} | {len(all_g) - len(g)} | {sum(r['marker_found'] for r in g)} "
            f"| {sum(r['ok'] for r in g)} | {sum(r['false_success'] for r in g)} "
            f"| {sum(r['suspect_success'] for r in g)} | {sum(r['missed'] for r in g)} "
            f"| {sum(r['restricted'] for r in g)} | {statistics.median(el):.2f} "
            f"| {_pct(el, 0.95):.2f} | {reqs} | {launches} |")
    out += ["", "## Per-case grid (P pass, F fail, n/a mode cannot apply, - not run)", "",
            "| case | category | " + " | ".join(modes) + " |",
            "|---|---|" + "---|" * len(modes)]
    cases = list(dict.fromkeys(r["case"] for r in rows))
    for c in cases:
        cells = []
        cat = next(r["category"] for r in rows if r["case"] == c)
        for m in modes:
            r = next((x for x in rows if x["case"] == c and x["mode"] == m), None)
            if r is None:
                cells.append("-")
            elif r["outcome"] == "n/a":
                cells.append("n/a")
            else:
                cells.append("P" if r["pass"] else "F")
        out.append(f"| {c} | {cat} | " + " | ".join(cells) + " |")
    return "\n".join(out) + "\n"


def main() -> int:
    if "--_pw-child" in sys.argv:
        i = sys.argv.index("--_pw-child")
        _pw_child(sys.argv[i + 1], sys.argv[i + 2] or None, sys.argv[i + 3])
        return 0
    ap = argparse.ArgumentParser()
    ap.add_argument("--label", required=True)
    ap.add_argument("--only", default="")
    ap.add_argument("--modes", default=",".join(ALL_MODES))
    ap.add_argument("--cases", default=str(Path(__file__).with_name("realworld.json")))
    ap.add_argument("--out-dir", default=str(Path(__file__).with_name("results")))
    ap.add_argument("--engine", choices=("headless-shell", "chromium", "chrome"), default="chromium")
    ap.add_argument("--categories", default="")
    args = ap.parse_args()
    modes = [m for m in args.modes.split(",") if m]
    bad = set(modes) - set(ALL_MODES)
    if bad:
        ap.error(f"unknown modes: {sorted(bad)}")
    only = {s for s in args.only.split(",") if s}
    categories = {s for s in args.categories.split(",") if s}
    cases = [c for c in json.loads(Path(args.cases).read_text())["cases"]
             if (not only or c["id"] in only) and (not categories or c["category"] in categories)]
    label = f"{args.label}-{args.engine}"
    rows = []
    for case in cases:
        for mode in modes:
            row = run_row(case, mode, args.engine)
            rows.append(row)
            status = "n/a" if row["outcome"] == "n/a" else ("PASS" if row["pass"] else "fail")
            print(f"{case['id']:22} {mode:15} {row['outcome']:14} marker={row['marker_found']!s:5}"
                  f" {row['elapsed']:6.2f}s {status}", flush=True)
    _mark_missed(rows)
    stamp = datetime.now().strftime("%Y%m%d-%H%M")
    base = Path(args.out_dir) / f"{label}-{stamp}"
    base.parent.mkdir(parents=True, exist_ok=True)
    # Not with_suffix(): labels may contain dots (e.g. "v0.1-rc"), which it would truncate.
    (base.parent / (base.name + ".json")).write_text(json.dumps(rows, indent=2) + "\n")
    (base.parent / (base.name + ".md")).write_text(summarize(rows, modes, label))
    print(f"wrote {base}.json/.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
