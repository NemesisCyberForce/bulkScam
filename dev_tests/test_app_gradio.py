#!/usr/bin/env python3
"""app.py (Gradio) against a fake gradio module: handlers, markdown output, case log, admin token. No network."""
import json, os, sys, tempfile, types
from unittest.mock import MagicMock
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.join(HERE, "..")
sys.path.insert(0, ROOT); sys.path.insert(0, HERE)

class GrError(Exception): pass
gr = MagicMock(); gr.Error = GrError; gr.Progress = lambda *a, **k: (lambda *x, **y: None)
sys.modules["gradio"] = gr
os.environ["IOC_STORE_PATH"] = os.path.join(tempfile.mkdtemp(), "cases.jsonl")
os.environ["CASE_ADMIN_TOKEN"] = "s3cret-token"
import app, forge_audit, web_scan, ioc_store, analyzer_core as ac, selftest as st  # noqa

R = []
def check(n, c, d=""):
    R.append(bool(c)); print(("PASS  " if c else "FAIL  ") + n + ("" if c else f"   -> {d}"))

files = {p: (c if isinstance(c, bytes) else c.encode()) for p, c in st.REPOS["hexsec"].items()}
rep = forge_audit.ForgeAnalyzer()._assess(
    provider="gitlab", mode="archive", repo_info="gitlab.com/g/p@main", blobs=[{"path": p, "size": len(b)} for p, b in files.items()],
    fetch=lambda p: (files.get(p), ""), members=files, notes=["note *with* <b>markup</b>"], T={}, t_all=0, say=lambda m: None,
    tree_truncated=False, max_files=40, backend=None, llm_max_files=6, system_prompt=None, user_template=None,
    check_osv=False, check_deps=False, artifact_max=2, abuse_key=None)
md = app.md_repo(rep)
check("md_repo shows provider/mode and the verdict", "gitlab" in md and "archive" in md and "FAKE" in md, md[:300])
check("md_repo shows IOC section with the honest caveat", "IOCs" in md and "not the scammer" in md and "telegram" in md.lower())
check("md_repo escapes markup from notes/targets", "<b>" not in md.replace("\\<b\\>", ""), md)
check("md_repo does not print API limit for archive mode", "GitHub limit" not in md)

app.ac.GitRepoAnalyzer  # exists
calls = {}
class FakeAnalyzer:
    def __init__(self, tok): calls["tok"] = tok
    def classify_url(self, url, **kw): calls.update(kw); calls["url"] = url; return rep
forge_audit.ForgeAnalyzer = FakeAnalyzer
out = app.run_repo_audit("https://gitlab.com/g/p", "ghp_TOKEN123", "Off (rules only)", "", "", "", 40, 6, "s", "u", "", 2, True, False,
                         "Archive download (no API limits)")
check("run_repo_audit passes mode 'archive' and the URL through", calls["mode"] == "archive" and calls["url"].endswith("g/p"), calls)
check("run_repo_audit: case is logged privately (unreviewed)", "Logged as case" in out[0] and "unreviewed" in out[0], out[0][-200:])
check("run_repo_audit: token never appears in markdown/report", "ghp_TOKEN123" not in out[0] and "ghp_TOKEN123" not in json.dumps(out[1]))
check("viewer gets the file list", out[3] is not None)
for bad in ("", "   "):
    try: app.run_repo_audit(bad, "", "Off (rules only)", "", "", "", 40, 6, "s", "u", "", 2, True, False); check("empty URL raises gr.Error", False)
    except GrError: check("empty URL raises gr.Error", True)
check("mode labels map to core modes", set(app.MODE_CHOICES.values()) == {"auto", "archive", "api"})

w = web_scan.analyze_html("<html><body><p>Press Win+R then Ctrl+V to verify you are human</p><button onclick=\"navigator.clipboard.writeText('powershell -enc AAAA')\">ok</button></body></html>", "https://evil.test/")
w.update({"url": "https://evil.test/", "final_url": "https://evil.test/", "provider": "web", "mode": "static", "timings": {"total": 0.1}})
mdw = app.md_web(w)
check("md_web: CRITICAL + static-view caveat", "CRITICAL" in mdw and "Static view only" in mdw, mdw[:200])
web_scan.scan_url = lambda u, progress=None: w
ow = app.run_web_audit("https://evil.test/")
check("run_web_audit logs a case too", "Logged as case" in ow[0])
check("md_web handles error reports", "Error" in app.md_web({"error": "HTTP 404"}))

check("cases_view: wrong token denied", app.cases_view("nope") == "Access denied.")
check("cases_view: empty token denied", app.cases_view("") == "Access denied.")
v = app.cases_view("s3cret-token")
check("cases_view: right token lists cases", "cases" in v and "evil.test" in v, v[:200])
cid = app.STORE.cases()[0]["case_id"]
check("cases_set: wrong token cannot change status", app.cases_set("x", cid, "confirmed") == "Access denied.")
check("cases_set: right token confirms", app.cases_set("s3cret-token", cid, "confirmed") == "Updated.")
ex = json.loads(app.cases_export("s3cret-token"))
check("cases_export: only confirmed, no URLs", len(ex) == 1 and "url" not in ex[0], ex)
check("cases_export: wrong token denied", app.cases_export("x") == "Access denied.")
print(f"\n{sum(R)}/{len(R)} Pruefungen bestanden"); sys.exit(0 if all(R) else 1)
