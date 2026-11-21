import os, sys
ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))  # Ordner mit analyzer_core.py
sys.path.insert(0, ROOT)
import sys, os, collections, time
import rules as R
cands = []
for root in ["/usr/bin", "/usr/sbin", "/usr/lib", "/usr/share", "/etc", "/usr/local/bin", "/opt"]:
    if not os.path.isdir(root): continue
    for dp, dn, fn in os.walk(root):
        for f in fn:
            p = os.path.join(dp, f)
            try:
                if os.path.islink(p) or os.path.getsize(p) > 600_000 or os.path.getsize(p) < 20: continue
                with open(p, "rb") as fh: head = fh.read(200)
            except OSError: continue
            if head.startswith(b"#!"):
                first = head.split(b"\n")[0].decode("latin-1")
                ext = ".sh" if ("sh" in first and "python" not in first and "perl" not in first) else ".py" if "python" in first else ".txt" if "perl" in first or "ruby" in first else ".js" if "node" in first else None
                if ext: cands.append((p, ext))
            elif f.endswith((".md", ".rst")) or (f.endswith((".html", ".htm", ".txt", ".pl", ".rb", ".php", ".yml", ".yaml")) and "doc" in dp):
                cands.append((p, os.path.splitext(f)[1] or ".txt"))
lv = collections.Counter(); noisy = []; t = time.time()
for p, ext in cands:
    try: text = open(p, encoding="utf-8", errors="replace").read()
    except OSError: continue
    res = R.scan_text(text, os.path.basename(p) + ("" if os.path.basename(p).endswith(ext) else ext))
    s = R.summarize({p: res}); lv[s["level"]] += 1
    if s["level"] != "LOW": noisy.append((s["malware_score"], p[-60:], sorted(s["rules_hit"]), [c["label"][:30] for c in s["combos"]]))
print(f"System-Korpus: {len(cands)} Dateien in {time.time()-t:.0f}s | Stufen: {dict(lv)}")
for n in sorted(noisy, reverse=True)[:8]: print("  ", n)
sys.exit(1 if (lv["MEDIUM"] or lv["HIGH"]) else 0)
