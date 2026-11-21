import hmac
import json
import os
import re
import tempfile
import time
from pathlib import Path

import gradio as gr

import analyzer_core as ac
import forge_audit
import ioc_store
import web_scan

# ------------------------------------------------------------------ ZeroGPU (optional)
try:
    import spaces
    ZEROGPU = True

    def gpu(duration):
        return spaces.GPU(duration=duration)
except ImportError:
    ZEROGPU = False

    def gpu(duration):
        return lambda f: f

STORE = ioc_store.CaseStore.from_env()          # None unless IOC_STORE_PATH is set (private case log)
ADMIN_TOKEN = os.environ.get("CASE_ADMIN_TOKEN", "")
MODE_CHOICES = {"Auto (GitHub: API, fallback archive)": "auto", "Archive download (no API limits)": "archive",
                "API (GitHub only)": "api"}

LOCAL_NAME = "Local (ZeroGPU)"
LOCAL_MODEL_ID = os.environ.get("LOCAL_MODEL_ID", "Qwen/Qwen2.5-Coder-1.5B-Instruct")
_local = {"tok": None, "model": None, "err": None}


def _load_local():
    """Einmal beim Start auf der CPU laden (nicht bei jedem Klick)."""
    if _local["model"] is not None or _local["err"]:
        return
    try:
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer
        _local["tok"] = AutoTokenizer.from_pretrained(LOCAL_MODEL_ID)
        _local["model"] = AutoModelForCausalLM.from_pretrained(LOCAL_MODEL_ID, torch_dtype=torch.bfloat16)
    except Exception as e:
        _local["err"] = f"{type(e).__name__}: {e}"


if ZEROGPU and os.environ.get("PRELOAD_LOCAL_MODEL", "1") == "1":
    _load_local()
LOCAL_OK = ZEROGPU and _local["model"] is not None


@gpu(90)  # NUR die Inferenz belegt GPU-Zeit - nicht GitHub-Fetch, Regeln oder UI
def _local_generate(jobs):
    import torch
    tok, model = _local["tok"], _local["model"].to("cuda")
    outs = []
    for system, user in jobs:
        try:
            text = tok.apply_chat_template(
                [{"role": "system", "content": system}, {"role": "user", "content": user}],
                tokenize=False, add_generation_prompt=True)
            inp = tok(text, return_tensors="pt").to("cuda")
            with torch.no_grad():
                out = model.generate(**inp, max_new_tokens=350, do_sample=False)
            outs.append(tok.decode(out[0][inp["input_ids"].shape[1]:], skip_special_tokens=True))
        except Exception as e:
            outs.append(f"__ERR__:{type(e).__name__}: {e}")
    return outs


class LocalBackend:
    def run(self, jobs):
        try:
            outs = _local_generate(jobs)
        except Exception as e:  # z.B. ZeroGPU-Kontingent aufgebraucht
            return [RuntimeError(f"ZeroGPU: {type(e).__name__}: {e}")] * len(jobs)
        return [RuntimeError(o[8:]) if isinstance(o, str) and o.startswith("__ERR__:") else o for o in outs]


# ------------------------------------------------------------------ Hilfen
def _safe(cls, *a, **kw):
    """Konstruktor-Aufruf, der Parameter weglaesst, die diese Gradio-Version nicht (mehr) kennt
    (Gradio 6 hat z.B. Blocks-Parameter verschoben)."""
    while True:
        try:
            return cls(*a, **kw)
        except TypeError as e:
            m = re.search(r"unexpected keyword argument '(\w+)'", str(e))
            if not m or m.group(1) not in kw:
                raise
            kw.pop(m.group(1))


def _esc(s) -> str:
    """Markdown-Sonderzeichen entschaerfen (Dateinamen/Texte kommen aus fremden Repos)."""
    return re.sub(r"([\\`*_{}\[\]<>()#+!|~])", r"\\\1", str(s))


def provider_defaults(p):
    pr = ac.PROVIDERS.get(p)
    if not pr:
        if p == LOCAL_NAME:
            return LOCAL_MODEL_ID, "", f"Local model on ZeroGPU ({LOCAL_MODEL_ID}). No key needed."
        return "", "", ""
    return pr["model"], pr["base_url"], pr["note"]


def build_backend(provider, key, model, base_url):
    if provider == LOCAL_NAME:
        if not LOCAL_OK:
            raise ValueError(f"Local model not available ({_local['err'] or 'no ZeroGPU'}).")
        return LocalBackend()
    cfg = ac.make_llm_config(provider, key, model, base_url)
    return ac.OpenAICompatBackend(cfg) if cfg else None


def _progress_fn(progress):
    def f(msg):
        try:
            progress(None, desc=msg)
        except Exception:
            pass
    return f


def run_llm_test(provider, key, model, base_url):
    try:
        backend = build_backend(provider, key, model, base_url)
        if backend is None:
            return "No provider selected."
        res = ac.test_llm(backend)
    except ValueError as e:
        return f"**LLM setting:** {_esc(e)}"
    if res["ok"]:
        return (f"**Connection ok** ({res['seconds']} s) - JSON response: "
                f"{'yes' if res['json_ok'] else 'NO, the model does not return JSON'}")
    return f"**LLM test failed** ({res['seconds']} s): {_esc(res['error'])}"


def md_iocs(rep):
    items = [i for i in rep.get("iocs", []) if i["strength"] in ("strong", "medium")]
    if not items:
        return []
    out = ["\n**Indicators (IOCs found in the content, not the scammer's real IPs/proxies):**"]
    for i in items[:25]:
        out.append(f"- {_esc(i['type'])}: `{_esc(i['value'])}` ({_esc(', '.join(i['where'][:2]))})")
    if len(items) > 25:
        out.append(f"- ... and {len(items) - 25} more (see JSON report)")
    return out


def _log_case(rep, url):
    """Optional private case log (only when IOC_STORE_PATH is set). Never raises."""
    if STORE is None:
        return ""
    try:
        c = STORE.add(rep, url)
    except Exception as e:  # logging must never break an audit
        return f"\n> Case log failed: {_esc(type(e).__name__)}"
    return f"\n> Logged as case `{c['case_id']}` (private, status: unreviewed)." if c else ""


def md_repo(rep):
    if "error" in rep:
        return f"### Error\n{_esc(rep['error'])}"
    cov = rep["coverage"]
    commits = rep["structure"].get("commits")
    out = [f"## {_esc(rep['verdict'])}",
           f"Confidence **{rep['confidence']}** - {_esc(rep['repo_info'])}"
           + (f" - {commits} Commits" if commits else "")
           + f" - Malware score **{rep['score']}/100** - Files {cov['scanned']}/{cov['scannable_total']} - "
             f"{rep['timings'].get('total', 0)} s", ""]
    out += [f"- {_esc(r)}" for r in rep["verdict_reasons"]]
    out.append(f"\nSource: **{_esc(rep.get('provider', 'github'))}** via **{_esc(rep.get('mode', 'api'))}**")
    out += [f"> {_esc(n)}" for n in rep.get("notes", [])]
    if cov["scanned"] < cov["scannable_total"]:
        out.append(f"\n> Only {cov['scanned']} of {cov['scannable_total']} scannable files checked - "
                   "increase 'Max. files per repo' (GitHub token recommended).")
    if cov["tree_truncated"]:
        out.append("\n> GitHub truncated the file tree - result incomplete.")
    if rep["meta_flags"]:
        out.append("\n**Metadata hints:** " + _esc("; ".join(rep["meta_flags"])))
    osv = rep["osv"]
    out.append(f"\n**OSV:** {osv['checked']} packages checked. {_esc(osv['note'])}")
    for m in osv["malicious"]:
        out.append(f"- Malware package: {_esc(m['ecosystem'])}/{_esc(m['package'])} ({_esc(', '.join(m['ids']))})")
    deps = rep["deps"]
    if deps["flagged"]:
        out.append("\n**Package check:**")
        out += [f"- {_esc(d['ecosystem'])}/{_esc(d['package'])}: {_esc('; '.join(d['flags']))}" for d in deps["flagged"]]
    if rep["artifacts"] or rep["artifact_errors"]:
        out.append("\n**Artifacts (release assets / archives):**")
        for a in rep["artifacts"]:
            mb = a["malwarebazaar"]
            mbt = (f"MalwareBazaar: {_esc(mb.get('signature'))}" if mb["found"]
                   else "MalwareBazaar: not found" if mb["checked"] else "MalwareBazaar: not queried")
            out.append(f"- {_esc(a['name'])} ({a['size_mb']} MB): **{a['risk_level']}** {a['score']}/100 - {mbt}"
                       + (f" - Archive password {_esc(a['archive_password'])}" if a["archive_password"] else "")
                       + (f" - Rules: {_esc(', '.join(a['rules'][:4]))}" if a["rules"] else ""))
            out += [f"  - {_esc(n)}" for n in a["notes"]]
        out += [f"- not checked: {_esc(e)}" for e in rep["artifact_errors"]]
    stars = rep["stars"]
    if stars.get("checked"):
        out.append(f"\n**Star sample:** {stars['sample']} accounts, {stars['low_activity']} with at most 2 starred "
                   f"repos, {stars['empty_profile']} without repos/followers, burst 24 h: {stars['burst24h_share']}")
    elif stars.get("note") and stars["note"] != "not requested":
        out.append(f"\n**Star analysis:** {_esc(stars['note'])}")
    if rep["leaks"]:
        out.append("\n**Possible credential leaks (redacted):** " + _esc("; ".join(rep["leaks"][:8])))
    g = rep.get("llm_gate") or {}
    if g.get("skipped_reason"):
        out.append(f"\n**LLM:** not used - {_esc(g['skipped_reason'])}.")
    elif g.get("mode") and rep["llm_results"] or g.get("sent"):
        out.append(f"\n**LLM audit** ({_esc(g.get('mode', ''))} mode: {g.get('sent', 0)} sent, "
                   f"{g.get('clear_by_rules', 0)} already clear by rules, {g.get('clean', 0)} clean - "
                   "only evidence-backed findings can escalate):")
        for r in rep["llm_results"]:
            x = r["result"]
            tagtxt = ""
            if x["classification"] in ("MALWARE_STEALER", "JAILBREAK_WRAPPER"):
                tagtxt = " **[confirmed]**" if x.get("confirmed") else " *[unconfirmed - ignored for the verdict]*"
            out.append(f"- {_esc(r['file'])}: {x['classification']} {x['confidence']}%{tagtxt} - {_esc(x['reasoning'])}")
    out += [f"\n**LLM error:** {_esc(e)}" for e in rep["llm_errors"]]
    out += [f"\n{_esc(e)}" for e in rep["llm_skipped"]]
    out += md_iocs(rep)
    out.append(f"\nTimings (s): {_esc(rep['timings'])}" + (f" - GitHub limit: {_esc(rep['rate_limit'])}" if rep.get("mode") == "api" else ""))
    return "\n".join(out)


def md_web(rep):
    if "error" in rep:
        return f"### Error\n{_esc(rep['error'])}"
    st = rep["stats"]
    out = [f"## {_esc(rep['verdict'])}", f"Confidence **{rep['confidence']}** - {_esc(rep['page_host'])} - "
           f"{st['visible_chars']} visible / {st['hidden_chars']} hidden chars, {st['scripts']} inline + "
           f"{st['external_scripts']} external scripts, {st['iframes']} iframes, {st['links']} links", ""]
    out += [f"- {_esc(r)}" for r in rep["verdict_reasons"]] or ["- no indicators in the static HTML"]
    out.append("\n> Static view only: the HTML as the server delivers it. Nothing was executed, no scripts/frames loaded.")
    out += md_iocs(rep)
    out.append(f"\nTimings (s): {_esc(rep['timings'])}")
    return "\n".join(out)


def md_bin(rep):
    mb = rep["malwarebazaar"]
    mbt = (f"known: {_esc(mb['signature'])}" if mb["found"] else
           "Hash not found" if mb["checked"] else f"not queried: {_esc(mb['note'])}")
    out = [f"## Risk: {rep['risk_level']} (score {rep['score']}/100)",
           f"{rep['size_mb']} MB - Entropy {rep['entropy']} - Packer: {_esc(', '.join(rep['packers']))}",
           f"\n**MalwareBazaar:** {mbt}", f"\n**SHA256:** `{rep['hashes']['sha256']}`"]
    out += [f"\n> {_esc(n)}" for n in rep["notes"]]
    if rep["heuristics"]:
        out.append("\n**Heuristics:** " + _esc(rep["heuristics"]))
    if rep["rules"] and rep["rules"]["rules_hit"]:
        out.append("\n**Rule hits:** " + _esc(", ".join(rep["rules"]["rules_hit"])))
    out += md_iocs(rep)
    out.append(f"\nTimings (s): {_esc(rep['timings'])}")
    return "\n".join(out)


def show_file(rep, name):
    f = ((rep or {}).get("sandbox_files") or {}).get(name)
    if not f:
        return "", ""
    return "\n".join(f.get("suspicious_lines", [])) or "(no hits)", f["content"]


def _result(rep, md):
    sf = rep.get("sandbox_files") or {}
    names = sorted(sf, key=lambda n: (-len(sf[n].get("suspicious_lines", [])), n))
    first = names[0] if names else None
    flagged, code = show_file(rep, first)
    slim = {k: v for k, v in rep.items() if k != "sandbox_files"}
    return md, slim, rep, gr.Dropdown(choices=names, value=first), flagged, code


# ------------------------------------------------------------------ Handler (NICHT GPU-dekoriert)
def run_repo_audit(url, gh_token, provider, key, model, base_url, max_files, llm_max, sys_prompt, user_tpl,
                   abuse_key, artifact_max, check_deps, deep_stars, mode="Auto (GitHub: API, fallback archive)",
                   llm_mode="Smart (rules first, only unclear files)", progress=gr.Progress()):
    if not (url or "").strip():
        raise gr.Error("Please enter a repository URL.")
    try:
        backend = build_backend(provider, key, model, base_url)
    except ValueError as e:
        raise gr.Error(f"LLM setting: {e}")
    rep = forge_audit.ForgeAnalyzer(gh_token or None).classify_url(
        url.strip(), mode=MODE_CHOICES.get(mode, "auto"), max_files=int(max_files), backend=backend,
        llm_mode="all" if str(llm_mode).startswith("All") else "smart",
        llm_max_files=int(llm_max), system_prompt=sys_prompt, user_template=user_tpl, check_deps=bool(check_deps),
        artifact_max=int(artifact_max), deep_stars=bool(deep_stars),
        abuse_key=abuse_key or os.environ.get("ABUSECH_API_KEY"), progress=_progress_fn(progress))
    return _result(rep, md_repo(rep) + _log_case(rep, url.strip()))


def run_web_audit(url, progress=gr.Progress()):
    if not (url or "").strip():
        raise gr.Error("Please enter a page URL.")
    rep = web_scan.scan_url(url.strip(), progress=_progress_fn(progress))
    return _result(rep, md_web(rep) + _log_case(rep, url.strip()))


def _admin_ok(token):
    return bool(STORE and ADMIN_TOKEN and hmac.compare_digest(str(token or ""), ADMIN_TOKEN))


def cases_view(token):
    if not _admin_ok(token):
        return "Access denied."
    cs = STORE.cases()
    out = [f"### {len(cs)} cases (private, quarantine until confirmed)"]
    for g in STORE.clusters():
        out.append(f"- **Cluster of {g['size']}:** {_esc(', '.join(g['targets'][:6]))} - shared: {_esc(', '.join(g['shared_iocs'][:6]))}")
    out.append("\n| case | target | verdict | masche | status | IOCs |\n|---|---|---|---|---|---|")
    for c in cs[:200]:
        out.append(f"| `{c['case_id']}` | {_esc(c['target'])} | {_esc(c['verdict'][:48])} | {_esc(c['masche'])} | "
                   f"{_esc(c['human_status'])} | {len(c['iocs'])} |")
    return "\n".join(out)


def cases_set(token, cid, status):
    if not _admin_ok(token):
        return "Access denied."
    return "Updated." if STORE.set_status((cid or "").strip(), status) else "Unknown case id or status."


def cases_export(token):
    if not _admin_ok(token):
        return "Access denied."
    return json.dumps(STORE.export_confirmed(), indent=1, ensure_ascii=False)


def run_binary_audit(url, zip_pw, abuse_key, progress=gr.Progress()):
    if not (url or "").strip():
        raise gr.Error("Please enter a URL.")
    try:
        with tempfile.TemporaryDirectory() as td:
            dest = Path(td) / "sample.bin"
            t0 = time.perf_counter()
            progress(None, desc="Download ...")
            name = ac.BinaryAnalyzer.download_file(url.strip(), dest)
            dl = round(time.perf_counter() - t0, 2)
            progress(None, desc="Analyzing ...")
            rep = ac.BinaryAnalyzer.analyze_file(
                dest, display_name=name, abuse_key=abuse_key or os.environ.get("ABUSECH_API_KEY"),
                extra_passwords=[zip_pw.encode()] if zip_pw else None)
            rep["timings"]["download"] = dl
    except Exception as e:
        raise gr.Error(f"{type(e).__name__}: {e}")
    return _result(rep, md_bin(rep))


# ------------------------------------------------------------------ UI
def make_viewer():
    state = gr.State()
    gr.Markdown("### Sandbox Inspector (read-only, no execution)")
    dd = _safe(gr.Dropdown, label="File", choices=[], interactive=True)
    flagged = _safe(gr.Textbox, label="Rule hits (same as in the audit)", lines=4, interactive=False)
    code = _safe(gr.Code, label="Content", interactive=False, lines=25)
    dd.input(show_file, [state, dd], [flagged, code])
    return state, dd, flagged, code


CHOICES = ["Off (rules only)"] + list(ac.PROVIDERS) + ([LOCAL_NAME] if LOCAL_OK else [])

with _safe(gr.Blocks, title="Scam & Malware Audit Engine") as demo:
    gr.Markdown("# Repository & Payload Static Audit Engine\n"
                "Detects fake AI wrappers, sales funnels and payloads - static analysis, nothing is executed.")
    with gr.Tab("Repository Audit"):
        url = gr.Textbox(label="Repository URL (GitHub, GitLab, Codeberg/Gitea/Forgejo, Bitbucket, SourceHut, Hugging Face, Gist)",
                         placeholder="https://github.com/owner/repo")
        with gr.Accordion("Settings (tokens, scan scope, LLM)", open=False):
            gh_token = _safe(gr.Textbox, label="GitHub token (optional)", type="password",
                             info="No scope needed. 60 -> 5000 requests/hour. Empty = GITHUB_TOKEN from Space secrets.")
            mode = gr.Radio(list(MODE_CHOICES), value=list(MODE_CHOICES)[0], label="How to fetch the repo",
                            info="Archive = one ZIP download, no API limits, no metadata. API = GitHub REST (metadata, stars, releases).")
            max_files = gr.Slider(10, 150, value=40, step=5, label="Max. files per repo")
            artifact_max = _safe(gr.Slider, 0, 5, value=2, step=1, label="Check release assets/archives (0 = off)",
                                 info="Scammers hide the payload there. Max. 25 MB per file, never executed.")
            check_deps = gr.Checkbox(value=True, label="Package check (PyPI/npm: age, typosquats)")
            deep_stars = gr.Checkbox(value=False, label="Star analysis (GitHub token required, approx. 60 API calls)")
            abuse_key = _safe(gr.Textbox, label="abuse.ch auth key (optional)", type="password",
                              info="Free. Without a key MalwareBazaar is not queried.")
            provider = gr.Dropdown(CHOICES, value=CHOICES[0], label="LLM provider")
            note = gr.Markdown()
            key = gr.Textbox(label="API key / HF token", type="password")
            model = gr.Textbox(label="Model ID")
            base_url = gr.Textbox(label="Base URL (Custom only)")
            llm_mode = gr.Radio(["Smart (rules first, only unclear files)", "All top files (more tokens)"],
                                value="Smart (rules first, only unclear files)", label="What goes to the LLM",
                                info="Smart: files with rule risk 1-49 or obfuscation. Clear and clean files are not sent. "
                                     "A LLM verdict only counts with a verbatim quote that the rules back up.")
            llm_max = gr.Slider(1, 40, value=6, step=1, label="Max. files sent to LLM (highest rule risk first; saves free quotas)")
            provider.change(provider_defaults, provider, [model, base_url, note])
            llm_test_btn = gr.Button("Test LLM")
            llm_test_out = gr.Markdown()
            llm_test_btn.click(run_llm_test, [provider, key, model, base_url], llm_test_out)
        with gr.Accordion("Edit prompt", open=False):
            sys_prompt = _safe(gr.Textbox, value=ac.DEFAULT_SYSTEM_PROMPT, lines=10, label="System prompt")
            user_tpl = _safe(gr.Textbox, value=ac.DEFAULT_USER_TEMPLATE, lines=5,
                             label="User template ({filename} {rule_hints} {code})")
            gr.Markdown("JSON format and injection protection are appended automatically.")
            gr.Button("Reset").click(lambda: (ac.DEFAULT_SYSTEM_PROMPT, ac.DEFAULT_USER_TEMPLATE),
                                             None, [sys_prompt, user_tpl])
        go = gr.Button("Check repository", variant="primary")
        r_md = gr.Markdown()
        with gr.Accordion("Report (JSON)", open=False):
            r_json = gr.JSON()
        r_state, r_dd, r_flag, r_code = make_viewer()
        go.click(run_repo_audit,
                 [url, gh_token, provider, key, model, base_url, max_files, llm_max, sys_prompt, user_tpl,
                  abuse_key, artifact_max, check_deps, deep_stars, mode, llm_mode],
                 [r_md, r_json, r_state, r_dd, r_flag, r_code])

    with gr.Tab("Web Page Audit"):
        gr.Markdown("Static check of an ordinary web page (ClickFix / fake installer / fake AI-tool pages). "
                    "Only the delivered HTML is parsed - nothing is executed, JavaScript-rendered content is not visible.")
        w_url = gr.Textbox(label="Page URL", placeholder="https://...")
        w_go = gr.Button("Check page", variant="primary")
        w_md = gr.Markdown()
        with gr.Accordion("Report (JSON)", open=False):
            w_json = gr.JSON()
        w_state, w_dd, w_flag, w_code = make_viewer()
        w_go.click(run_web_audit, [w_url], [w_md, w_json, w_state, w_dd, w_flag, w_code])

    if STORE is not None and ADMIN_TOKEN:
        with gr.Tab("Case log (private)"):
            gr.Markdown("Scam-network case log. Quarantine by default; only `confirmed` cases can be exported. "
                        "Indications, not proof of fraud.")
            c_tok = gr.Textbox(label="Admin token", type="password")
            c_show = gr.Button("Show cases and clusters")
            c_md = gr.Markdown()
            c_show.click(cases_view, [c_tok], c_md)
            with gr.Row():
                c_id = gr.Textbox(label="Case id")
                c_status = gr.Dropdown(list(ioc_store.STATUSES), value="confirmed", label="Status")
            c_set = gr.Button("Set status")
            c_msg = gr.Markdown()
            c_set.click(cases_set, [c_tok, c_id, c_status], c_msg)
            c_exp = gr.Button("Export confirmed (public-safe JSON)")
            c_out = gr.Code(language="json", label="Export")
            c_exp.click(cases_export, [c_tok], c_out)

    with gr.Tab("Binary / Archive Sandbox"):
        b_url = gr.Textbox(label="File URL (direct or Google Drive)", placeholder="https://...")
        b_pw = gr.Textbox(label="Archive password from the README (optional)")
        b_key = _safe(gr.Textbox, label="abuse.ch auth key (optional)", type="password",
                      info="Free. Without a key MalwareBazaar is not queried.")
        b_go = gr.Button("Check file", variant="primary")
        b_md = gr.Markdown()
        with gr.Accordion("Report (JSON)", open=False):
            b_json = gr.JSON()
        b_state, b_dd, b_flag, b_code = make_viewer()
        b_go.click(run_binary_audit, [b_url, b_pw, b_key], [b_md, b_json, b_state, b_dd, b_flag, b_code])

if __name__ == "__main__":
    demo.launch()
