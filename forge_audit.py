# ============================================
# LICENSE & SOURCE
# ============================================
# Licensed under AGPL3 + ESOL v2.1
# Source: https://github.com/NemesisCyberForce/bulkScam
# ============================================
"""Repo audit for ANY supported git forge (GitHub, GitLab, Gitea/Forgejo/Codeberg, Bitbucket, SourceHut,
Hugging Face, GitHub Gists).

Two ways to get the files, one shared analysis pipeline (same rules, same decide(), same report keys):
  * ARCHIVE mode: download the platform's ZIP/TGZ once (one request, no API rate limit), read it in memory.
  * API mode: the existing GitHub REST path (metadata, stars, releases) in analyzer_core.GitRepoAnalyzer.
Auto mode = GitHub via API; on a rate-limit error it falls back to the archive download.
Hugging Face (tree API + resolve) and gists (GitHub API) are fetched file by file.
Nothing from the target is ever executed.
"""
from __future__ import annotations

import re
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path, PurePosixPath
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import quote

import analyzer_core as ac
import archives
import iocs
import providers
import rules

REPO_ARCHIVE_MAX = 60 * 1024 * 1024        # download size of a repo archive
REPO_UNPACKED_MAX = 250 * 1024 * 1024
REPO_ENTRIES_MAX = 20000
HF_TREE_PAGES = 5
HF_PREFIX = {"model": "", "space": "spaces/", "dataset": "datasets/"}
HF_API = {"model": "models", "space": "spaces", "dataset": "datasets"}
MODES = ("auto", "archive", "api")


def _strip_common_root(files: Dict[str, bytes]) -> Dict[str, bytes]:
    """GitHub/GitLab archives wrap everything in '<repo>-<ref>/' - remove it so paths look like the repo."""
    tops = {p.split("/", 1)[0] for p in files if "/" in p}
    if len(tops) == 1 and all("/" in p for p in files):
        root = next(iter(tops)) + "/"
        return {p[len(root):]: b for p, b in files.items()}
    return files


class ForgeAnalyzer(ac.GitRepoAnalyzer):

    # ------------------------------------------------------------------ public entry
    def classify_url(self, url: str, *, mode: str = "auto", max_files: int = 40, backend=None, llm_max_files: int = 6,
                     system_prompt: Optional[str] = None, user_template: Optional[str] = None, check_osv: bool = True,
                     check_deps: bool = True, artifact_max: int = 2, abuse_key: Optional[str] = None,
                     deep_stars: bool = False, progress: Optional[Callable[[str], None]] = None) -> Dict:
        say = progress or (lambda m: None)
        mode = mode if mode in MODES else "auto"
        kw = dict(max_files=max_files, backend=backend, llm_max_files=llm_max_files, system_prompt=system_prompt,
                  user_template=user_template, check_osv=check_osv, check_deps=check_deps, artifact_max=artifact_max,
                  abuse_key=abuse_key, progress=progress)
        get_json = providers.json_getter(ac.safe_get, ac.UA)
        try:
            ref = providers.parse_url(url, get_json)
        except providers.UnsupportedURL as e:
            return {"error": str(e)}
        except Exception as e:
            return {"error": ac.scrub(f"{type(e).__name__}: {e}", self.token)}
        try:
            if ref.provider == "github":
                if mode == "archive":
                    return self._classify_archive(ref, get_json, say, **kw)
                rep = self.classify_repo(url, deep_stars=deep_stars, **kw)
                if mode == "auto" and "error" in rep and "rate limit" in rep["error"].lower():
                    say("GitHub API limit reached - switching to archive download ...")
                    alt = self._classify_archive(ref, get_json, say, **kw)
                    alt["notes"] = ["GitHub API rate limit reached - repository was scanned via archive download "
                                    "(no metadata/star/release analysis)."] + alt.get("notes", [])
                    return alt
                return rep
            if mode == "api" and ref.provider not in ("huggingface", "gist"):
                return {"error": f"API mode is only implemented for GitHub. Use Auto or Archive for {ref.provider}."}
            if ref.provider == "gist":
                return self._classify_gist(ref, say, **kw)
            if ref.provider == "huggingface":
                return self._classify_hf(ref, say, **kw)
            return self._classify_archive(ref, get_json, say, **kw)
        except ac.GitHubError as e:
            return {"error": str(e), "rate_limit": self.rate}
        except Exception as e:
            return {"error": ac.scrub(f"{type(e).__name__}: {e}", self.token)}

    # ------------------------------------------------------------------ archive mode
    def _classify_archive(self, ref: providers.RepoRef, get_json, say, **kw) -> Dict:
        T: Dict[str, float] = {}
        t_all = time.perf_counter()
        t = time.perf_counter()
        last_err = ""
        data = b""
        used = ""
        for br in providers.branch_candidates(ref, get_json):
            url = providers.archive_url(ref, br)
            say(f"Downloading archive ({ref.provider}, ref {br}) ...")
            try:
                with tempfile.TemporaryDirectory() as td:
                    dest = Path(td) / "repo.bin"
                    ac.BinaryAnalyzer.download_file(url, dest, max_bytes=REPO_ARCHIVE_MAX)
                    data = dest.read_bytes()
                used = br
                break
            except ac.UnsafeURL as e:
                return {"error": f"Blocked: {e}"}
            except ValueError as e:
                last_err = str(e)
                if last_err.startswith("HTTP 4"):
                    continue
                return {"error": ac.scrub(f"Archive download failed: {last_err}", self.token)}
            except Exception as e:
                return {"error": ac.scrub(f"Archive download failed: {type(e).__name__}: {e}", self.token)}
        if not data:
            return {"error": f"Repository archive could not be downloaded ({last_err or 'no response'}) - "
                             "private repo, wrong URL or unknown branch."}
        T["download"] = round(time.perf_counter() - t, 2)
        t = time.perf_counter()
        say("Reading archive in memory ...")
        files, skipped, _pwd, anotes, fmt = archives.read_archive(
            data, "repo", None, max_depth=0, max_entries=REPO_ENTRIES_MAX, max_total=REPO_UNPACKED_MAX)
        if files is None:
            return {"error": "Archive downloaded but not readable: " + "; ".join(anotes or ["unknown format"])}
        files = _strip_common_root(files)
        skipped = {p.split("/", 1)[-1] if "/" in p else p: why for p, why in skipped.items()}
        T["unpack"] = round(time.perf_counter() - t, 2)
        blobs = [{"path": p, "size": len(b)} for p, b in files.items()]
        blobs += [{"path": p, "size": ac.MAX_REPO_FILE + 1} for p in skipped]  # too large: listed, not read
        return self._assess(provider=ref.provider, mode="archive", repo_info=f"{ref.slug}@{used}", blobs=blobs,
                            fetch=lambda p: (files.get(p), "" if p in files else "not in archive"), members=files,
                            notes=list(anotes), T=T, t_all=t_all, say=say, tree_truncated=False, **kw)

    # ------------------------------------------------------------------ gist
    def _classify_gist(self, ref: providers.RepoRef, say, **kw) -> Dict:
        T: Dict[str, float] = {}
        t_all = time.perf_counter()
        say("GitHub: loading gist ...")
        g = self._gh(f"/gists/{ref.repo}")
        files: Dict[str, bytes] = {}
        errors: List[str] = []
        for name, f in (g.get("files") or {}).items():
            content = f.get("content")
            if content is not None and not f.get("truncated"):
                files[name] = content.encode("utf-8", "replace")
            elif f.get("raw_url"):
                try:
                    r = ac.safe_get(f["raw_url"], headers={"User-Agent": ac.UA})
                    try:
                        files[name] = b"".join(r.iter_content(65536))[:ac.MAX_REPO_FILE] if r.status_code == 200 else b""
                    finally:
                        r.close()
                except Exception as e:
                    errors.append(f"{name}: {type(e).__name__}")
        owner = (g.get("owner") or {}).get("login", ref.owner)
        blobs = [{"path": p, "size": len(b)} for p, b in files.items()]
        rep = self._assess(provider="gist", mode="api", repo_info=f"gist:{owner}/{ref.repo}", blobs=blobs,
                           fetch=lambda p: (files.get(p), "" if p in files else "missing"), members={},
                           notes=errors, T=T, t_all=t_all, say=say, tree_truncated=False,
                           description=g.get("description") or "", **kw)
        return rep

    # ------------------------------------------------------------------ Hugging Face
    def _hf_list(self, ref: providers.RepoRef, branch: str) -> Tuple[List[dict], bool]:
        base = f"https://huggingface.co/api/{HF_API[ref.kind]}/{ref.owner}/{ref.repo}/tree/{quote(branch, safe='')}"
        url, out, pages = f"{base}?recursive=true", [], 0
        while url and pages < HF_TREE_PAGES:
            r = ac.safe_get(url, headers={"User-Agent": ac.UA, "Accept": "application/json"})
            try:
                if r.status_code == 404:
                    raise ac.GitHubError("Hugging Face repo/branch not found (or private).")
                if r.status_code != 200:
                    raise ac.GitHubError(f"Hugging Face API error {r.status_code}")
                body = b"".join(r.iter_content(65536))[:5_000_000]
                nxt = re.search(r'<([^>]+)>;\s*rel="next"', r.headers.get("Link", ""))
            finally:
                r.close()
            import json as _json
            out += [i for i in _json.loads(body) if i.get("type") == "file"]
            url, pages = (nxt.group(1) if nxt else None), pages + 1
        return out, bool(url)

    def _hf_fetch(self, ref: providers.RepoRef, branch: str, path: str) -> Tuple[Optional[bytes], str]:
        url = (f"https://huggingface.co/{HF_PREFIX[ref.kind]}{ref.owner}/{ref.repo}/resolve/"
               f"{quote(branch, safe='')}/{quote(path, safe='/')}")
        try:
            r = ac.safe_get(url, headers={"User-Agent": ac.UA})
            try:
                if r.status_code != 200:
                    return None, f"HTTP {r.status_code}"
                buf, n = [], 0
                for chunk in r.iter_content(65536):
                    n += len(chunk)
                    if n > ac.MAX_REPO_FILE:
                        return None, "too large"
                    buf.append(chunk)
                return b"".join(buf), ""
            finally:
                r.close()
        except Exception as e:
            return None, type(e).__name__

    def _classify_hf(self, ref: providers.RepoRef, say, **kw) -> Dict:
        T: Dict[str, float] = {}
        t_all = time.perf_counter()
        branch = ref.ref or "main"
        say("Hugging Face: file tree ...")
        items, truncated = self._hf_list(ref, branch)
        blobs = [{"path": i["path"], "size": i.get("size") or 0} for i in items if i.get("path")]
        weights = [b["path"] for b in blobs if b["path"].lower().endswith((".pkl", ".pickle", ".pt", ".pth", ".bin", ".ckpt"))]
        notes = []
        if weights:
            notes.append(f"{len(weights)} pickle-capable weight file(s) found ({', '.join(weights[:3])}"
                         f"{', ...' if len(weights) > 3 else ''}): contents are NOT inspected (pickle opcode scan is not "
                         "built yet) - prefer .safetensors and never load unknown .pkl/.pt files.")
        cache: Dict[str, Tuple[Optional[bytes], str]] = {}

        def fetch(path: str):
            if path not in cache:
                cache[path] = self._hf_fetch(ref, branch, path)
            return cache[path]
        return self._assess(provider="huggingface", mode="api", repo_info=f"huggingface.co/{HF_PREFIX[ref.kind]}"
                            f"{ref.owner}/{ref.repo}@{branch}", blobs=blobs, fetch=fetch, members={}, notes=notes, T=T,
                            t_all=t_all, say=say, tree_truncated=truncated, **kw)

    # ------------------------------------------------------------------ shared pipeline
    def _assess(self, *, provider: str, mode: str, repo_info: str, blobs: List[dict],
                fetch: Callable[[str], Tuple[Optional[bytes], str]], members: Dict[str, bytes], notes: List[str],
                T: Dict[str, float], t_all: float, say, tree_truncated: bool, max_files: int, backend, llm_max_files: int,
                system_prompt: Optional[str], user_template: Optional[str], check_osv: bool, check_deps: bool,
                artifact_max: int, abuse_key: Optional[str], progress=None, description: str = "") -> Dict:
        def lap(name, t0):
            T[name] = round(time.perf_counter() - t0, 2)

        sp, ut = ac.check_prompts(system_prompt, user_template)
        paths = [f["path"] for f in blobs]
        bad_tree = [p for p in paths if p.lower().endswith(ac.EXEC_EXT) and not p.lower().endswith((".bat", ".cmd", ".ps1"))]
        archives_in = [p for p in paths if p.lower().endswith(ac.ARCHIVE_EXT)]
        chosen, n_cand, big = self._pick_files(blobs, max_files)
        say(f"Loading {len(chosen)} of {n_cand} scannable files ...")
        t = time.perf_counter()
        if members:
            fetched = [fetch(f["path"]) for f in chosen]
        else:
            with ThreadPoolExecutor(max_workers=8) as ex:
                fetched = list(ex.map(lambda f: fetch(f["path"]), chosen))
        lap("fetch_files", t)

        say("Scanning rules ...")
        t = time.perf_counter()
        sandbox_files: Dict[str, Dict] = {}
        per_file: Dict[str, Dict] = {}
        fulltext: Dict[str, str] = {}
        fetch_errors: List[str] = []
        readme_pw: List[bytes] = []
        for f, (raw, err) in zip(chosen, fetched):
            if raw is None:
                fetch_errors.append(f"{f['path']}: {err}")
                continue
            preview, scan, text = ac._preview_and_scan(raw, f["path"])
            sandbox_files[f["path"]] = preview
            if scan:
                per_file[f["path"]] = scan
                fulltext[f["path"]] = text
                if f["path"].lower().rsplit("/", 1)[-1].startswith("readme"):
                    readme_pw += rules.archive_passwords(text)
        desc_scan = rules.scan_text(description, "(repo-description).md") if description.strip() else None
        summary = rules.summarize({**per_file, **({"(repo-description)": desc_scan} if desc_scan else {})})
        lap("rules", t)

        packages = ac.collect_packages(fulltext) if (check_osv or check_deps) else []
        osv = {"checked": 0, "malicious": [], "note": "skipped"}
        if check_osv:
            say("OSV: checking package names ...")
            t = time.perf_counter()
            osv = ac.osv_check(packages)
            lap("osv", t)
        deps = {"checked": 0, "flagged": [], "note": "skipped"}
        if check_deps:
            say("Registry: checking package age/typosquats ...")
            t = time.perf_counter()
            deps = ac.deps_check(packages)
            lap("deps", t)

        artifacts, artifact_errors, artifact_skipped = [], [], 0
        if artifact_max > 0 and members:
            t = time.perf_counter()
            artifacts, artifact_errors, artifact_skipped = self._artifacts_from_memory(
                members, list(dict.fromkeys(readme_pw)), abuse_key, artifact_max, sandbox_files, say)
            lap("artifacts", t)

        llm_results, llm_errors, llm_skipped = [], [], []
        if backend is not None:
            say("LLM audit ...")
            t = time.perf_counter()
            llm_results, llm_errors, llm_skipped = self._llm_audit(per_file, fulltext, backend, sp, ut, llm_max_files)
            lap("llm", t)

        ioc_list = iocs.extract({**fulltext, **({"(repo-description)": description} if description else {})},
                                readme_pw, [a["sha256"] for a in artifacts])
        coverage = len(per_file) / max(n_cand, 1)
        code_scanned = sum(1 for p in per_file if PurePosixPath(p).suffix.lower() in rules.CODE_EXT)
        flags: List[str] = []
        verdict, confidence, reasons = ac.decide(
            summary, len(per_file), osv["malicious"], [], bad_tree, flags, llm_results, coverage, code_scanned,
            extra={"artifacts": artifacts, "deps_flagged": deps["flagged"], "archives": archives_in})
        T["total"] = round(time.perf_counter() - t_all, 2)
        return {
            "verdict": verdict, "confidence": confidence, "verdict_reasons": reasons, "score": summary["malware_score"],
            "rules": summary, "meta_flags": flags, "provider": provider, "mode": mode, "notes": notes,
            "structure": {"python_file_count": sum(1 for p in paths if p.lower().endswith(".py")),
                          "executables_in_tree": bad_tree, "archives": archives_in, "release_assets": [],
                          "releases": [], "commits": None},
            "coverage": {"scanned": len(per_file), "scannable_total": n_cand, "requested_max": max_files,
                         "skipped_too_large": big, "fetch_errors": fetch_errors, "tree_truncated": tree_truncated},
            "osv": osv, "deps": deps, "artifacts": artifacts, "artifact_errors": artifact_errors,
            "artifact_skipped": artifact_skipped, "stars": {"checked": False, "note": "not available in this mode"},
            "llm_results": llm_results, "llm_errors": llm_errors, "llm_skipped": llm_skipped,
            "leaks": summary["leaks"], "iocs": ioc_list, "rate_limit": self.rate, "timings": T,
            "pattern_scores": {"legit": len(summary["real_training_files"]) * 10,
                               "fake": len(summary["wrapper_signals"]) * 5, "malware_risk": summary["malware_score"]},
            "repo_info": repo_info, "sandbox_files": sandbox_files,
        }

    def _artifacts_from_memory(self, members: Dict[str, bytes], passwords: List[bytes], abuse_key: Optional[str],
                               limit: int, sandbox_files: Dict[str, Dict], say):
        """Archives/executables inside the downloaded repo: analysed like in the Binary tab (README passwords tried)."""
        cands = [(p, b) for p, b in members.items()
                 if p.lower().endswith(ac.ARTIFACT_EXT) and 0 < len(b) <= ac.ARTIFACT_MAX_BYTES]
        cands.sort(key=lambda pb: (not pb[0].lower().endswith(ac.EXEC_EXT), len(pb[1])))
        results, errors = [], []
        for name, blob in cands[:limit]:
            say(f"Checking artifact: {name} ...")
            try:
                with tempfile.TemporaryDirectory() as td:
                    dest = Path(td) / "artifact.bin"
                    dest.write_bytes(blob)
                    rep = ac.BinaryAnalyzer.analyze_file(dest, display_name=name, abuse_key=abuse_key,
                                                         extra_passwords=passwords)
            except Exception as e:
                errors.append(ac.scrub(f"{name}: {type(e).__name__}: {e}", self.token))
                continue
            results.append({
                "name": name, "origin": "repo", "size_mb": rep["size_mb"], "sha256": rep["hashes"]["sha256"],
                "risk_level": rep["risk_level"], "score": rep["score"], "malwarebazaar": rep["malwarebazaar"],
                "packers": rep["packers"], "heuristics": rep["heuristics"], "notes": rep["notes"],
                "rules": list(rep["rules"]["rules_hit"]) if rep["rules"] else [],
                "archive_password": rep["archive_password"], "members": len(rep["sandbox_files"]),
            })
            for n, f in list(rep["sandbox_files"].items())[:25]:
                sandbox_files[f"[artifact] {name} :: {n}"] = f
        return results, errors, max(0, len(cands) - limit)
