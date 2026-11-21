import os, sys
ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))  # Ordner mit analyzer_core.py
sys.path.insert(0, ROOT)
import sys, os, time, collections, site, json
import importlib, rules as R
def collect():
    roots = ["/usr/lib/python3", "/usr/lib/python3.12", "/usr/local/lib/python3.12", "/usr/lib/python3/dist-packages"] + site.getsitepackages()
    out = []
    for r in dict.fromkeys(roots):
        if not os.path.isdir(r): continue
        for dp, dn, fn in os.walk(r):
            for f in fn:
                if f.endswith((".py", ".md", ".rst", ".txt", ".js", ".sh", ".json", ".yml", ".yaml", ".toml", ".cfg")) or f == "METADATA":
                    p = os.path.join(dp, f)
                    try:
                        if os.path.getsize(p) <= 2_000_000: out.append(p)
                    except OSError: pass
    return out
def run(files, verbose=True, per_rule_examples=3):
    cnt = collections.Counter(); ex = collections.defaultdict(list); fcount = collections.Counter(); levels = collections.Counter()
    t = time.time(); nbytes = 0
    for p in files:
        try: text = open(p, encoding="utf-8", errors="replace").read()
        except OSError: continue
        nbytes += len(text)
        name = os.path.basename(p) if os.path.basename(p) != "METADATA" else "METADATA.md"
        res = R.scan_text(text, name)
        seen = set()
        for h in res["hits"]:
            cnt[h.rule] += 1
            if h.rule not in seen:
                fcount[h.rule] += 1; seen.add(h.rule)
            if len(ex[h.rule]) < per_rule_examples: ex[h.rule].append((p.replace("/usr/", "")[-70:], h.line, h.snippet[:90]))
        for c in res["combos"]:
            k = "COMBO:" + c["label"]; cnt[k] += 1; fcount[k] += 1; ex[k].append((p.replace("/usr/", "")[-70:], 0, ""))
        lvl = R.summarize({name: res})["level"]; levels[lvl] += 1
        if lvl != "LOW": ex["LEVEL:" + lvl].append((p.replace("/usr/", "")[-70:], R.summarize({name: res})["malware_score"], ",".join(sorted({h.rule for h in res["hits"] if h.sev != "INFO"}))))
    dt = time.time() - t
    if verbose:
        print(f"{len(files)} Dateien, {nbytes/1e6:.0f} MB Text, {dt:.1f}s ({nbytes/1e6/dt:.1f} MB/s)")
        for r, n in fcount.most_common(): print(f"{r:28} in {n:5} Dateien ({cnt[r]} Treffer)")
    if verbose: print("Datei-Stufen (einzeln bewertet):", dict(levels))
    run.levels = levels
    return cnt, fcount, ex
if __name__ == "__main__":
    files = collect(); print("Korpus:", len(files), "Dateien")
    cnt, fcount, ex = run(files)
    json.dump({k: v for k, v in ex.items()}, open(os.path.join(__import__("tempfile").gettempdir(), "fp_examples.json"), "w"), indent=1, default=str)
    sys.exit(1 if (run.levels["MEDIUM"] or run.levels["HIGH"]) else 0)
