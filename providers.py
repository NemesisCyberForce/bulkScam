# ============================================
# LICENSE & SOURCE
# ============================================
# Licensed under AGPL3 + ESOL v2.1
# Source: https://github.com/NemesisCyberForce/bulkScam
# ============================================
"""Git forges: parse any repo URL, detect the platform (known hosts + probing for self-hosted GitLab/Gitea/Forgejo)
and build the archive (ZIP/TGZ) download URL. Pure string logic + two tiny SSRF-safe probes; no scanning here.

Platforms: github, gist, gitlab, gitea (Gitea/Forgejo/Codeberg), bitbucket, sourcehut, huggingface.
URL patterns of the platforms are written from memory of their public URL schemes (not verified live in this build).
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Callable, List, Optional, Tuple
from urllib.parse import quote, urlparse

KNOWN_HOSTS = {
    "github.com": "github", "www.github.com": "github", "gist.github.com": "gist",
    "gitlab.com": "gitlab", "codeberg.org": "gitea", "gitea.com": "gitea", "bitbucket.org": "bitbucket",
    "git.sr.ht": "sourcehut", "huggingface.co": "huggingface", "hf.co": "huggingface",
}
_RESERVED_GH = {"orgs", "topics", "settings", "marketplace", "sponsors", "features", "about", "login", "pricing",
                "search", "explore", "collections", "events", "notifications", "pulls", "issues"}
_SEG = re.compile(r"^[A-Za-z0-9_.~@+-]{1,100}$")


class UnsupportedURL(ValueError):
    pass


@dataclass
class RepoRef:
    provider: str
    host: str
    owner: str            # GitLab: full namespace incl. subgroups ("group/sub")
    repo: str
    ref: Optional[str] = None
    kind: str = "repo"    # repo | gist | model | space | dataset
    scheme: str = "https"

    @property
    def slug(self) -> str:
        return f"{self.host}/{self.owner}/{self.repo}"

    @property
    def web_url(self) -> str:
        return f"{self.scheme}://{self.host}/{self.owner}/{self.repo}"


def _normalize(url: str) -> str:
    u = (url or "").strip()
    if not u or len(u) > 500:
        raise UnsupportedURL("Please enter a repository URL.")
    m = re.match(r"^(?:ssh://)?git@([A-Za-z0-9.-]+)[:/](.+)$", u)  # git@host:owner/repo.git
    if m:
        return f"https://{m.group(1)}/{m.group(2)}"
    if "://" not in u:
        if re.match(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", u):  # owner/repo -> GitHub
            return f"https://github.com/{u}"
        return "https://" + u
    return u


def _segments(path: str) -> List[str]:
    segs = [s for s in path.split("/") if s]
    for s in segs:
        if not _SEG.match(s) or s in (".", ".."):
            raise UnsupportedURL("Invalid characters in the URL path.")
    return segs


def _strip_git(name: str) -> str:
    return name[:-4] if name.lower().endswith(".git") else name


def _ref_after(segs: List[str], markers: Tuple[str, ...], skip: int = 0) -> Optional[str]:
    for i, s in enumerate(segs):
        if s in markers and i + 1 + skip < len(segs):
            return segs[i + 1 + skip]
    return None


def _probe_default(host: str, get_json: Callable[[str], Tuple[int, object]]) -> Optional[str]:
    """Unknown host: Gitea/Forgejo answer /api/v1/version, GitLab answers /api/v4/version (200, or 401 JSON)."""
    code, data = get_json(f"https://{host}/api/v1/version")
    if code == 200 and isinstance(data, dict) and "version" in data:
        return "gitea"
    code, data = get_json(f"https://{host}/api/v4/version")
    if (code == 200 and isinstance(data, dict) and "version" in data) or \
            (code == 401 and isinstance(data, dict) and "message" in data):
        return "gitlab"
    return None


def parse_url(url: str, get_json: Optional[Callable[[str], Tuple[int, object]]] = None) -> RepoRef:
    """-> RepoRef. get_json(url) -> (status, parsed_json|None) is only used for unknown hosts (platform probing)."""
    u = urlparse(_normalize(url))
    host = (u.hostname or "").lower()
    if u.scheme not in ("http", "https") or not host or u.username or u.password:
        raise UnsupportedURL("Only http/https URLs without credentials are supported.")
    segs = _segments(u.path)
    prov = KNOWN_HOSTS.get(host)
    if prov is None:
        if host.startswith("gitlab."):
            prov = "gitlab"
        elif get_json is not None:
            prov = _probe_default(host, get_json)
        if prov is None:
            raise UnsupportedURL(f"Unknown host '{host}': neither GitLab nor Gitea/Forgejo detected. "
                                 "Use the Binary/Archive tab with a direct archive URL instead.")
    if prov == "github":
        if len(segs) < 2 or segs[0].lower() in _RESERVED_GH:
            raise UnsupportedURL("Invalid GitHub URL (expected: https://github.com/owner/repo)")
        ref = segs[3] if len(segs) > 3 and segs[2] in ("tree", "blob") else None
        return RepoRef("github", "github.com", segs[0], _strip_git(segs[1]), ref)
    if prov == "gist":
        if not segs:
            raise UnsupportedURL("Invalid gist URL.")
        gid = segs[1] if len(segs) > 1 else segs[0]
        if not re.fullmatch(r"[0-9a-fA-F]{8,64}", gid):
            raise UnsupportedURL("Invalid gist id.")
        return RepoRef("gist", "gist.github.com", segs[0] if len(segs) > 1 else "gist", gid, None, "gist")
    if prov == "gitlab":
        if "-" in segs:
            i = segs.index("-")
            proj, tail = segs[:i], segs[i + 1:]
        else:
            proj, tail = segs, []
        if len(proj) < 2:
            raise UnsupportedURL("Invalid GitLab URL (expected: https://gitlab.com/group/project)")
        ref = tail[1] if len(tail) > 1 and tail[0] in ("tree", "blob") else None
        return RepoRef("gitlab", host, "/".join(proj[:-1]), _strip_git(proj[-1]), ref)
    if prov == "gitea":
        if len(segs) < 2:
            raise UnsupportedURL("Invalid URL (expected: https://host/owner/repo)")
        ref = segs[4] if len(segs) > 4 and segs[2] == "src" and segs[3] in ("branch", "tag", "commit") else None
        return RepoRef("gitea", host, segs[0], _strip_git(segs[1]), ref)
    if prov == "bitbucket":
        if len(segs) < 2:
            raise UnsupportedURL("Invalid Bitbucket URL.")
        ref = segs[3] if len(segs) > 3 and segs[2] == "src" else None
        return RepoRef("bitbucket", host, segs[0], _strip_git(segs[1]), ref)
    if prov == "sourcehut":
        if len(segs) < 2 or not segs[0].startswith("~"):
            raise UnsupportedURL("Invalid SourceHut URL (expected: https://git.sr.ht/~owner/repo)")
        ref = segs[3] if len(segs) > 3 and segs[2] == "tree" else None
        return RepoRef("sourcehut", host, segs[0][1:], segs[1], ref)
    if prov == "huggingface":
        kind, rest = "model", segs
        if segs and segs[0] in ("spaces", "datasets"):
            kind, rest = ("space" if segs[0] == "spaces" else "dataset"), segs[1:]
        if len(rest) < 2:
            raise UnsupportedURL("Invalid Hugging Face URL (expected: https://huggingface.co/owner/name)")
        ref = rest[3] if len(rest) > 3 and rest[2] in ("tree", "blob", "resolve") else None
        return RepoRef("huggingface", "huggingface.co", rest[0], rest[1], ref, kind)
    raise UnsupportedURL("Unsupported platform.")


# --------------------------------------------------------------------------------- archives
def archive_url(r: RepoRef, branch: str) -> str:
    b = quote(branch, safe="/")
    if r.provider == "github":
        return f"https://github.com/{r.owner}/{r.repo}/archive/{b}.zip"
    if r.provider == "gitlab":
        return f"https://{r.host}/{r.owner}/{r.repo}/-/archive/{b}/{r.repo}-{branch.replace('/', '-')}.zip"
    if r.provider == "gitea":
        return f"https://{r.host}/{r.owner}/{r.repo}/archive/{b}.zip"
    if r.provider == "bitbucket":
        return f"https://bitbucket.org/{r.owner}/{r.repo}/get/{b}.zip"
    if r.provider == "sourcehut":
        return f"https://git.sr.ht/~{r.owner}/{r.repo}/archive/{b}.tar.gz"
    raise UnsupportedURL(f"No archive download for {r.provider}.")


def branch_candidates(r: RepoRef, get_json: Optional[Callable[[str], Tuple[int, object]]] = None) -> List[str]:
    """Branch names to try, best first. Explicit ref from the URL always wins; otherwise ask the platform API
    for the default branch (when reachable) and fall back to HEAD/main/master."""
    if r.ref:
        return [r.ref]
    found: Optional[str] = None
    try:
        if get_json is not None:
            if r.provider == "gitlab":
                code, d = get_json(f"https://{r.host}/api/v4/projects/{quote(r.owner + '/' + r.repo, safe='')}")
                found = d.get("default_branch") if code == 200 and isinstance(d, dict) else None
            elif r.provider == "gitea":
                code, d = get_json(f"https://{r.host}/api/v1/repos/{r.owner}/{r.repo}")
                found = d.get("default_branch") if code == 200 and isinstance(d, dict) else None
            elif r.provider == "bitbucket":
                code, d = get_json(f"https://api.bitbucket.org/2.0/repositories/{r.owner}/{r.repo}")
                found = ((d or {}).get("mainbranch") or {}).get("name") if code == 200 and isinstance(d, dict) else None
    except Exception:
        found = None
    base = ["HEAD"] if r.provider in ("github", "sourcehut") else []
    out = ([found] if found else []) + base + ["main", "master"]
    return list(dict.fromkeys(b for b in out if b))


def json_getter(safe_get: Callable, ua: str, cap: int = 200_000, timeout: int = 6) -> Callable[[str], Tuple[int, object]]:
    """Builds the get_json helper from analyzer_core.safe_get (SSRF-checked, size-capped, never raises)."""
    def get(url: str):
        try:
            r = safe_get(url, headers={"User-Agent": ua, "Accept": "application/json"}, timeout=timeout)
        except Exception:
            return 0, None
        try:
            buf, n = [], 0
            for chunk in r.iter_content(65536):
                n += len(chunk)
                if n > cap:
                    return r.status_code, None
                buf.append(chunk)
            try:
                return r.status_code, json.loads(b"".join(buf))
            except Exception:
                return r.status_code, None
        finally:
            r.close()
    return get
