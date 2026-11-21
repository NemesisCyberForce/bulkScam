#!/usr/bin/env python3
"""Runs ALL tests offline.   python dev_tests/run_all.py [--fast]
--fast skips the long corpus/fuzz stages (about 30 s instead of 6-10 min)."""
import os, subprocess, sys, time
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.abspath(os.path.join(HERE, ".."))
FAST = "--fast" in sys.argv
D = "dev_tests"
stages = [("Selftest (rules, core, archives, mock server)", [sys.executable, f"{D}/selftest.py"], True),
          ("Forges, web scan, IOCs, case store", [sys.executable, f"{D}/test_forges.py"], True),
          ("Gradio app (fake gradio module)", [sys.executable, f"{D}/test_app_gradio.py"], True),
          ("Robustness (broken archives, huge tree, LLM garbage)", [sys.executable, f"{D}/robust_core.py"], True),
          ("Selftest + package corpus", [sys.executable, f"{D}/selftest.py", "--corpus"], False),
          ("False positives: installed packages as repos", [sys.executable, f"{D}/fp_repos.py"], False),
          ("False positives: system scripts/docs", [sys.executable, f"{D}/fp_system.py"], False),
          ("False positives: ~24k single files", [sys.executable, f"{D}/fp_corpus.py"], False),
          ("Fuzz/ReDoS of all rules", [sys.executable, f"{D}/fuzz_rules.py"], False)]
results = []
for name, cmd, fast_ok in stages:
    if FAST and not fast_ok:
        results.append((name, "skipped", 0)); print(f"{'skipped':8} {name}"); continue
    t = time.time()
    p = subprocess.run(cmd, cwd=ROOT, env={**os.environ, "PYTHONPATH": ROOT}, capture_output=True, text=True)
    tail = (p.stdout.strip().splitlines() or [""])[-1][:100]
    results.append((name, "OK" if p.returncode == 0 else "FAILED", time.time() - t))
    print(f"{results[-1][1]:8} {name}  ({results[-1][2]:.0f}s)  {tail}")
    if p.returncode != 0:
        print(p.stdout[-1500:], p.stderr[-800:])
bad = [r for r in results if r[1] == "FAILED"]
print("\nTOTAL:", "ALL OK" if not bad else f"{len(bad)} stage(s) failed")
sys.exit(1 if bad else 0)
