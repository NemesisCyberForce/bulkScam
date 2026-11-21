import os, sys
ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))  # Ordner mit analyzer_core.py
sys.path.insert(0, ROOT)
import sys, os, collections, time, site
import rules as R
roots = [r for r in dict.fromkeys(["/usr/lib/python3/dist-packages"] + site.getsitepackages()) if os.path.isdir(r)]
EXT = (".py", ".md", ".rst", ".txt", ".js", ".sh", ".json", ".yml", ".yaml", ".toml", ".cfg")
repos = collections.defaultdict(list)
for root in roots:
    for entry in sorted(os.listdir(root)):
        d = os.path.join(root, entry)
        if entry.endswith((".dist-info", ".egg-info")) or entry.startswith("__"): continue
        if os.path.isdir(d):
            for dp, dn, fn in os.walk(d):
                for f in fn:
                    if f.endswith(EXT):
                        p = os.path.join(dp, f)
                        try:
                            if os.path.getsize(p) <= 1_000_000: repos[entry].append(p)
                        except OSError: pass
# METADATA (README der Pakete) dem jeweiligen Paket zuordnen
for root in roots:
    for entry in os.listdir(root):
        if entry.endswith(".dist-info"):
            pkg = entry.split("-")[0].replace("_", "-").lower()
            m = os.path.join(root, entry, "METADATA")
            if os.path.exists(m):
                for k in list(repos):
                    if k.lower().replace("_", "-") == pkg: repos[k].append(m)
levels = collections.Counter(); noisy = []; t0 = time.time(); n_files = 0
for name, files in repos.items():
    files = files[:150]                      # wie max_files im Tool (grosszuegig)
    per = {}
    for p in files:
        try: text = open(p, encoding="utf-8", errors="replace").read()
        except OSError: continue
        fn = os.path.basename(p); fn = "README.md" if fn == "METADATA" else fn
        per[os.path.relpath(p, os.path.dirname(os.path.dirname(p)))[-80:] + "#" + str(len(per))] = R.scan_text(text, fn)
        n_files += 1
    s = R.summarize(per)
    levels[s["level"]] += 1
    if s["level"] != "LOW" or s["combos"]:
        noisy.append((s["malware_score"], name, sorted(s["rules_hit"]), [c["label"][:40] for c in s["combos"]]))
print(f"{len(repos)} Paket-'Repos', {n_files} Dateien, {time.time()-t0:.0f}s")
print("Repo-Stufen:", dict(levels))
for sc, name, hit, cb in sorted(noisy, reverse=True)[:25]: print(f"  {sc:3} {name:28} {hit} {cb}")
sys.exit(1 if (levels["MEDIUM"] or levels["HIGH"]) else 0)
