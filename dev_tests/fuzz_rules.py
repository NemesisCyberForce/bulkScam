import os, sys
ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))  # Ordner mit analyzer_core.py
sys.path.insert(0, ROOT)
import sys, time, random, os, base64, zlib
import rules as R
random.seed(7)
def fname(rule):
    s = rule.scope
    return {"any": "x.py", "code": "x.py", "doc": "README.md", "agent": ".cursorrules"}.get(s, s)
slow = []
issues = []
N = 300_000
t_all = time.time()
for rule in R.RULES:
    fn = fname(rule)
    needles = list(rule.need) or ["a"]
    variants = []
    for nd in needles[:3]:
        variants.append((nd + " ") * (N // (len(nd) + 1)))                 # Trigger-Wort massenhaft
        variants.append(nd * (N // max(len(nd), 1)))                       # ohne Trennzeichen
        variants.append(nd + ("a" * N))                                    # Trigger + langer Rest ohne Zeilenumbruch
        variants.append((nd + "(" + "x" * 50 + "\n") * (N // 60))          # viele kurze Zeilen
    for v in variants:
        t = time.time(); R.scan_text(v, fn); dt = time.time() - t
        if dt > 1.5: slow.append((round(dt, 2), rule.id, v[:25].replace("\n", "\\n")))
print(f"{len(R.RULES)} Regeln x 12 Varianten a {N//1000} KB: {time.time()-t_all:.0f}s gesamt")
print("langsam (>1.5s):", sorted(slow, reverse=True)[:10] or "keine")
issues += slow
# gezielte pathologische Faelle
cases = {
 "html-comment ohne Ende": "<!-- ai agent " * 20000,
 "cmdclass ohne Ende": "cmdclass = {" + "a" * 500000,
 "dup2 Ketten": "os.dup2(s.fileno(), 0)" * 20000,
 "klammern": "exec(" + "(" * 100000,
 "base64-Flut": " ".join(base64.b64encode(os.urandom(60)).decode() for _ in range(5000)),
 "hex-Flut": " ".join(os.urandom(40).hex() for _ in range(5000)),
 "verschachtelt b64": base64.b64encode(base64.b64encode(base64.b64encode(b"A" * 5000))).decode(),
 "zlib-Bombe in b64": base64.b64encode(zlib.compress(b"A" * 50_000_000)).decode(),
 "nur Newlines": "\n" * 2_000_000,
 "NUL + Muell": "\x00" * 100000 + "exec(x)",
 "Unicode-Flut": "\u200b" * 200000 + "a" * 100,
 "lange Zeile 3MB": "var a=" + "1,".join(["x"] * 1_500_000),
}
for name, txt in cases.items():
    for fn in ("x.py", "README.md", ".cursorrules", "x.js"):
        t = time.time()
        try: R.scan_text(txt, fn); err = ""
        except Exception as e: err = f"FEHLER {type(e).__name__}: {e}"
        dt = time.time() - t
        if dt > 2 or err:
            print(f"  AUFFAELLIG {name:24} {fn:13} {dt:.1f}s {err}"); issues.append((name, fn))
print("pathologische Faelle geprueft")
# Robustheit gegen kaputte Eingaben
for bad in ["", "\ufeff", b"\xff\xfe\x00".decode("latin-1"), "\ud800" if False else "x", "a" * 10, "\r\n" * 5]:
    R.scan_text(bad, "x.py"); R.scan_text(bad, "README.md")
for fn in ["", "x", ".", "a/b/c", "..\\..\\x.py", "x.ipynb", "a" * 500 + ".py"]:
    R.scan_text("print(1)", fn)
R.scan_text('{"cells": "kaputt"}', "x.ipynb"); R.scan_text("{nicht json", "x.ipynb")
print("kaputte Dateinamen/Notebooks: ok")
print("FUZZ-ERGEBNIS:", "OK" if not issues else issues)
sys.exit(1 if issues else 0)
