import os, sys
ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))  # Ordner mit analyzer_core.py
sys.path.insert(0, ROOT)
import sys, os, io, zipfile, struct, time, tempfile, json, random
from pathlib import Path
import selftest as T
import analyzer_core as ac
srv, B = T.start_server()
ac.GITHUB_API, ac.GITHUB_RAW, ac.OSV_URL, ac.MB_URL = B, B + "/raw", B + "/osv", B + "/mb"
ac.PYPI_URL, ac.NPM_URL = B + "/pypi", B + "/npm"
ac.check_public_url = lambda u: u
bad = []
def attempt(name, fn):
    t = time.time()
    try: r = fn(); dt = time.time() - t
    except Exception as e: bad.append(name); print(f"FEHLER {name}: {type(e).__name__}: {e}"); return None
    print(f"ok   {name} ({dt:.2f}s)"); return r
def wz(path, entries, comp=zipfile.ZIP_DEFLATED):
    with zipfile.ZipFile(path, "w", comp) as z:
        for n, d in entries: z.writestr(n, d)
tmp = Path(tempfile.mkdtemp())
# --- kaputte / manipulierte Archive
good = tmp / "g.zip"; wz(good, [("a.py", "print(1)")]); raw = good.read_bytes()
(tmp / "trunc.zip").write_bytes(raw[:len(raw) // 2])
(tmp / "garbage.zip").write_bytes(b"PK\x03\x04" + os.urandom(500))
(tmp / "empty.bin").write_bytes(b"")
(tmp / "nul.bin").write_bytes(b"\x00" * 100000)
wz(tmp / "names.zip", [("../../etc/passwd", "x"), ("/abs/path.py", "exec(base64.b64decode('AA'))"), ("a" * 300 + ".py", "x"), ("dup.py", "1"), ("dup.py", "2"), ("ctl\x01\x02.py", "x"), ("dir/", ""), ("empty.py", "")])
inner = io.BytesIO(); 
with zipfile.ZipFile(inner, "w") as z: z.writestr("deep.py", "exec(base64.b64decode('AA'))")
wz(tmp / "nested.zip", [("inner.zip", inner.getvalue())])
wz(tmp / "manyzeros.zip", [(f"z{i}.bin", b"\x00" * 1_600_000) for i in range(120)])
(tmp / "evilcrc.zip").write_bytes(raw.replace(b"print(1)", b"print(2)"))   # CRC passt nicht
(tmp / "rar.rar").write_bytes(b"Rar!\x1a\x07\x01\x00" + os.urandom(200))
(tmp / "7z.7z").write_bytes(b"7z\xbc\xaf\x27\x1c" + os.urandom(200))
for f in sorted(tmp.iterdir()):
    r = attempt(f"analyze_file {f.name}", lambda f=f: ac.BinaryAnalyzer.analyze_file(f, f.name, abuse_key=None))
    if r and f.name == "names.zip": print("      Namen:", [k[:20] for k in r["sandbox_files"]][:8])
    if r and f.name == "manyzeros.zip": print("      Eintraege:", len(r["sandbox_files"]), "| uebersprungen:", sum(1 for v in r["sandbox_files"].values() if v["type"] == "SKIPPED"))
# --- riesiger Dateibaum + kaputte API-Antworten
big_tree = [{"type": "blob", "path": f"src/mod{i}/file{i}.py", "size": 100 + i % 5000} for i in range(30000)] + \
           [{"type": "blob", "path": "weird/none_size.py", "size": None}, {"type": "blob", "path": "weird/nosize.py"},
            {"type": "commit", "path": "submodule"}, {"type": "blob", "path": "unicode/\u00e4\u00f6\u00fc \u4e2d\u6587.py", "size": 10}]
T.REPOS["bigtree"] = {"README.md": "x\n"}
orig = T.Handler.do_GET
def patched(self):
    if "/repos/x/bigtree/git/trees" in self.path:
        return self._send({"truncated": True, "tree": big_tree})
    return orig(self)
T.Handler.do_GET = patched
r = attempt("classify_repo mit 30.000 Dateien im Baum", lambda: ac.GitRepoAnalyzer().classify_repo("https://github.com/x/bigtree", max_files=40))
if r: print("      ", r.get("verdict", r.get("error"))[:60], "| scannbar:", r["coverage"]["scannable_total"], "| truncated:", r["coverage"]["tree_truncated"], "| Zeit:", r["timings"]["total"])
# --- LLM-Antworten: pathologisch
t = time.time(); ac.extract_json("{" * 200000); print(f"extract_json 200k '{{': {time.time()-t:.2f}s")
t = time.time(); ac.extract_json('{"a": "' + "x" * 500000); print(f"extract_json offener String: {time.time()-t:.2f}s")
for junk in [None, "", "[]", "[1,2]", '{"classification": 5, "confidence": "abc", "key_indicators": {"x": 1}}', '{"classification":["a"],"confidence":null}']:
    try: ac.validate_llm_result(ac.extract_json(junk) if isinstance(junk, str) else junk)
    except Exception as e: bad.append("validate"); print("FEHLER validate", repr(junk)[:40], type(e).__name__, e)
print("validate_llm_result robust gegen Muell")
# --- Prompt-Injektion ueber Dateinamen/Platzhalter im User-Template
job = ac.build_job("evil{code}{filename}.py", "print(1)\n", [], "S", "F={filename} H={rule_hints} C={code}")
print("Platzhalter-Injektion im Dateinamen:", "evil{code}" in job[1] and job[1].count("UNTRUSTED_CODE_") == 2)
print("\nFEHLER GESAMT:", bad or "keine")
sys.exit(1 if bad else 0)
