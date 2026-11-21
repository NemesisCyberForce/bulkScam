# ============================================
# LICENSE & SOURCE
# ============================================
# Licensed under AGPL3 + ESOL v2.1
# Source: https://github.com/NemesisCyberForce/bulkScam
# ============================================
"""Static audit of an ordinary web page (ClickFix / fake installer / fake AI-tool pages).

Only the HTML that the server returns is parsed. Nothing is executed, no JavaScript is run, no subresource is
fetched (scripts, iframes, images stay URLs). Pages that are rendered by JavaScript are therefore only partly
visible - the report says so. The fetch goes through analyzer_core.safe_get (SSRF checks incl. redirects, size cap).
"""
from __future__ import annotations

import re
import time
from html.parser import HTMLParser
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import analyzer_core as ac
import iocs
import rules

MAX_PAGE = 2 * 1024 * 1024
VOID = {"br", "hr", "img", "input", "meta", "link", "area", "base", "col", "embed", "source", "track", "wbr", "param"}
_HIDDEN_STYLE = re.compile(r"(?i)display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(?:\.0+)?\s*(?:;|$)|"
                           r"font-size\s*:\s*0(?:px|pt|em|rem)?\s*(?:;|$)|(?:left|top|text-indent)\s*:\s*-\d{3,}|"
                           r"(?:width|height)\s*:\s*0(?:px)?\s*(?:;|$)|clip\s*:\s*rect\(0")
EXEC_LINK = (".exe", ".msi", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".jar", ".apk", ".dmg", ".pkg", ".lnk", ".iso")
ARCH_LINK = (".zip", ".rar", ".7z", ".tar.gz", ".tgz")
LURE = re.compile(r"(?i)\b(?:crack(?:ed)?|keygen|free\s+download|download\s+now|installer|setup|activator|patch|"
                  r"unlock(?:ed)?|premium\s+free|no\s+restrictions?|uncensored|jailbreak(?:ed)?|wormgpt|fraudgpt)\b")

_CLIP_WRITE = re.compile(r"(?i)navigator\s*\.\s*clipboard\s*\.\s*write(?:Text)?\s*\(|execCommand\s*\(\s*['\"]copy['\"]|"
                         r"clipboardData\s*\.\s*setData\s*\(")
_SHELL = re.compile(
    r"(?i)(?:powershell(?:\.exe)?\b[^\n]{0,80}?\s-(?:e|enc|encodedcommand|w(?:indowstyle)?\s+hidden|nop|ep\s+bypass)\b|"
    r"\bmshta(?:\.exe)?\s+(?:https?:|vbscript:)|\bcmd(?:\.exe)?\s*/[ck]\b|"
    r"\bcurl\s[^|\n]{0,200}\|\s*(?:ba|z)?sh\b|\bwget\s[^|\n]{0,200}\|\s*(?:ba|z)?sh\b|\bcertutil\s+-urlcache|"
    r"\bmsiexec(?:\.exe)?\s+/i\s*https?:|\bfinger\s+\S{1,60}@|\biex\s*\(|\bInvoke-Expression\b|"
    r"\birm\s+https?://[^\s|]{1,200}\s*\|\s*iex\b|\bbitsadmin\s+/transfer\b)")
_CF_RUN = re.compile(r"(?i)win(?:dows)?\s*(?:key\s*)?\+\s*r\b|press\s+(?:the\s+)?windows\s+key|run\s+dialog|open\s+(?:the\s+)?run\b")
_CF_PASTE = re.compile(r"(?i)ctrl\s*\+\s*v\b|cmd\s*\+\s*v\b|\bpaste\b[^\n]{0,40}\b(?:enter|run|terminal|dialog)\b")
_CF_VERIFY = re.compile(r"(?i)verify\s+(?:that\s+)?you(?:'|’)?(?:re|\s+are)\s+(?:a\s+)?human|not\s+a\s+robot|captcha|"
                        r"i(?:'|’)?m\s+not\s+a\s+robot|human\s+verification|fix\s+(?:this\s+)?(?:issue|error)|to\s+verify")
_AI_INJECT = re.compile(r"(?i)ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions|you\s+are\s+an?\s+(?:ai|assistant|llm)\b|"
                        r"system\s+prompt|as\s+an?\s+ai\s+(?:agent|assistant)|do\s+not\s+tell\s+the\s+user")
_JS_APP = re.compile(r"""(?i)id\s*=\s*["'](?:root|app|__next|__nuxt)["']""")


class _Page(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title = ""
        self.visible: List[str] = []
        self.hidden: List[str] = []
        self.scripts: List[str] = []
        self.script_src: List[str] = []
        self.iframes: List[Dict] = []
        self.links: List[Tuple[str, str]] = []
        self.forms: List[Dict] = []
        self.meta_refresh: List[str] = []
        self.handlers: List[str] = []
        self.has_password_input = False
        self._stack: List[Tuple[str, bool]] = []
        self._in = ""  # script/style/title
        self._buf: List[str] = []
        self._link_text: Optional[List[str]] = None
        self._link_href = ""

    def _hidden_now(self) -> bool:
        return bool(self._stack and self._stack[-1][1])

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        for k, v in a.items():
            if k.startswith("on") and v:
                self.handlers.append(f"{k}={v[:300]}")
        hid = self._hidden_now() or ("hidden" in a) or bool(_HIDDEN_STYLE.search(a.get("style", ""))) \
            or a.get("aria-hidden") == "true"
        if tag in ("script", "style", "title"):
            self._in, self._buf = tag, []
            if tag == "script" and a.get("src"):
                self.script_src.append(a["src"])
        elif tag == "iframe":
            self.iframes.append({"src": a.get("src", ""), "hidden": hid or a.get("width") in ("0", "1")
                                 or a.get("height") in ("0", "1")})
        elif tag == "meta" and a.get("http-equiv", "").lower() == "refresh":
            self.meta_refresh.append(a.get("content", ""))
        elif tag == "a" and a.get("href"):
            self._link_href, self._link_text = a["href"], []
        elif tag == "form":
            self.forms.append({"action": a.get("action", ""), "method": a.get("method", "get").lower()})
        elif tag == "input" and a.get("type", "").lower() == "password":
            self.has_password_input = True
        if tag not in VOID:
            self._stack.append((tag, hid))

    def handle_endtag(self, tag):
        if self._in == tag:
            text = "".join(self._buf)
            if tag == "script" and text.strip():
                self.scripts.append(text)
            elif tag == "title":
                self.title = text.strip()[:200]
            self._in, self._buf = "", []
        if tag == "a" and self._link_text is not None:
            self.links.append((self._link_href, " ".join(self._link_text).strip()[:200]))
            self._link_text = None
        for i in range(len(self._stack) - 1, -1, -1):
            if self._stack[i][0] == tag:
                del self._stack[i:]
                break

    def handle_data(self, data):
        if self._in:
            if len(self._buf) < 5000:
                self._buf.append(data)
            return
        t = data.strip()
        if not t:
            return
        (self.hidden if self._hidden_now() else self.visible).append(t)
        if self._link_text is not None:
            self._link_text.append(t)


def _host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def _odd_host(h: str) -> Optional[str]:
    if not h:
        return None
    if h.startswith("xn--") or ".xn--" in h:
        return "punycode host"
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", h):
        return "IP address as host"
    if h.endswith((".top", ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".click", ".zip", ".mov")):
        return "high-abuse TLD"
    return None


def fetch_page(url: str) -> Tuple[str, str, str, int]:
    """-> (html, final_url, content_type, status). SSRF-safe, size-capped, text types only."""
    r = ac.safe_get(url, headers={"User-Agent": "Mozilla/5.0 (compatible; BulkScamStaticAudit/1.0)",
                                  "Accept": "text/html,application/xhtml+xml,text/plain;q=0.8"})
    try:
        ct = (r.headers.get("Content-Type") or "").lower()
        if r.status_code != 200:
            raise ValueError(f"HTTP {r.status_code}")
        if ct and not any(x in ct for x in ("html", "text/", "xml", "json")):
            raise ValueError(f"Not a web page (Content-Type: {ct[:60]}). Use the Binary/Archive tab for files.")
        buf, n = [], 0
        for chunk in r.iter_content(65536):
            n += len(chunk)
            if n > MAX_PAGE:
                raise ValueError(f"Page larger than {MAX_PAGE // 1048576} MB - not scanned.")
            buf.append(chunk)
        raw = b"".join(buf)
        m = re.search(r"charset=([\w-]+)", ct)
        enc = m.group(1) if m else "utf-8"
        try:
            html = raw.decode(enc, "replace")
        except LookupError:
            html = raw.decode("utf-8", "replace")
        return html, getattr(r, "url", url) or url, ct, r.status_code
    finally:
        r.close()


def analyze_html(html: str, page_url: str) -> Dict:
    """Pure function (no network): HTML -> findings, rule hits, IOCs, verdict."""
    p = _Page()
    try:
        p.feed(html)
        p.close()
    except Exception:
        pass
    page_host = _host(page_url)
    findings: List[Dict] = []

    def add(fid: str, sev: str, text: str) -> None:
        findings.append({"id": fid, "severity": sev, "text": text})

    visible = " ".join(p.visible)[:60000]
    hidden = " ".join(p.hidden)[:60000]
    script_text = "\n".join(p.scripts)[:600000]
    handler_text = "\n".join(p.handlers)[:50000]

    # --- ClickFix: clipboard write + shell command, or the typical instruction text
    clip = bool(_CLIP_WRITE.search(script_text) or _CLIP_WRITE.search(handler_text))
    shell = _SHELL.search(script_text) or _SHELL.search(handler_text) or _SHELL.search(html[:400000])
    steps = sum(1 for rx in (_CF_RUN, _CF_PASTE, _CF_VERIFY) if rx.search(visible))
    if clip and shell:
        add("clickfix_clipboard_shell", "HIGH", "Page writes a shell command to your clipboard "
            f"(\"{shell.group(0)[:60]}...\") - classic ClickFix. Never paste it into Run/Terminal.")
    if steps >= 2 and (clip or shell):
        add("clickfix_instructions", "HIGH", "Page tells visitors to open Run/Terminal and paste something "
            "('verify you are human' style) while holding a clipboard/shell payload.")
    elif steps >= 2:
        add("clickfix_text_only", "MEDIUM", "Page text contains ClickFix-style instructions (Win+R / paste / verify) - "
            "the payload may be loaded by JavaScript that this static scan does not see.")
    elif shell:
        add("shell_command_in_page", "MEDIUM", f"Page contains a download-and-run command pattern (\"{shell.group(0)[:60]}\").")
    elif clip:
        add("clipboard_write", "INFO", "Page script writes to the clipboard (common on legitimate 'copy' buttons).")

    # --- hidden content / prompt injection for AI agents
    if hidden and _AI_INJECT.search(hidden):
        add("hidden_ai_injection", "MEDIUM", "Hidden page text addresses AI assistants (instruction-override phrases).")
    elif _AI_INJECT.search(visible):
        add("ai_injection_text", "INFO", "Visible text contains instruction-override phrases (may be a tutorial about them).")
    if len(hidden) > 400 and len(hidden) > len(visible):
        add("mostly_hidden_text", "MEDIUM", f"{len(hidden)} characters of hidden text vs {len(visible)} visible (keyword stuffing/cloaking).")

    # --- redirects, frames, forms, scripts
    for c in p.meta_refresh:
        m = re.search(r"(?i)url\s*=\s*['\"]?([^'\";\s]+)", c)
        if m and _host(urljoin(page_url, m.group(1))) not in ("", page_host):
            add("meta_refresh_offsite", "MEDIUM", f"Meta-refresh redirects to another host: {_host(urljoin(page_url, m.group(1)))}")
    for f in p.iframes:
        h = _host(urljoin(page_url, f["src"])) if f["src"] else ""
        if f["hidden"] and h and h != page_host:
            add("hidden_iframe", "MEDIUM", f"Hidden/zero-size iframe from {h}")
    for src in p.script_src:
        h = _host(urljoin(page_url, src))
        odd = _odd_host(h)
        if odd and h != page_host:
            add("script_odd_host", "MEDIUM", f"External script from {h} ({odd})")
    if p.has_password_input:
        for fm in p.forms:
            h = _host(urljoin(page_url, fm["action"])) if fm["action"] else ""
            if h and h != page_host:
                add("login_form_offsite", "MEDIUM", f"Password form submits to another host: {h}")

    # --- download links
    lure = bool(LURE.search(visible) or LURE.search(p.title))
    dl_exec, dl_arch, odd_links = [], [], []
    for href, text in p.links[:3000]:
        full = urljoin(page_url, href)
        hl = full.lower().split("?", 1)[0]
        h = _host(full)
        if hl.endswith(EXEC_LINK):
            dl_exec.append(full)
        elif hl.endswith(ARCH_LINK):
            dl_arch.append(full)
        odd = _odd_host(h)
        if odd and h != page_host:
            odd_links.append(f"{h} ({odd})")
    if dl_exec:
        add("exe_download_link", "MEDIUM" if (lure or _host(dl_exec[0]) != page_host) else "INFO",
            f"{len(dl_exec)} link(s) to executable files, e.g. {dl_exec[0][:100]}")
    if dl_arch and lure:
        add("archive_download_lure", "MEDIUM", f"Archive download link next to lure wording (crack/free/uncensored...): {dl_arch[0][:100]}")
    if odd_links:
        add("odd_link_hosts", "MEDIUM", "Links to unusual hosts: " + ", ".join(dict.fromkeys(odd_links[:5])))

    # --- run the shared rule engine over scripts (code) and visible text (claims/funnel)
    scans: Dict[str, Dict] = {}
    if script_text.strip():
        scans["inline-scripts.js"] = rules.scan_text(script_text, "inline-scripts.js")
    if visible.strip():
        scans["page-text.md"] = rules.scan_text(visible + ("\n" + hidden if hidden else ""), "page-text.md")
    summary = rules.summarize(scans) if scans else rules.summarize({})
    hit_ids = list(summary["rules_hit"])[:4]
    strong_combo = any(c["bonus"] >= 25 for c in summary["combos"])
    if summary["level"] == "HIGH" or strong_combo:
        add("rules_high", "HIGH", "Script code matches high-risk malware rules: " + ", ".join(hit_ids))
    elif summary["level"] == "MEDIUM":
        add("rules_medium", "MEDIUM", "Script/text matches risk rules: " + ", ".join(hit_ids))

    js_note = None
    if len(visible) < 300 and (p.scripts or p.script_src) and _JS_APP.search(html[:200000]):
        js_note = ("The page is rendered by JavaScript - the static scan sees only the empty shell, "
                   "so a clean result here means little.")

    ioc_texts = {"page": visible + "\n" + hidden, "scripts": script_text,
                 "links": "\n".join(urljoin(page_url, h) for h, _ in p.links[:3000])}
    ioc_list = iocs.extract(ioc_texts)

    high = [f for f in findings if f["severity"] == "HIGH"]
    med = [f for f in findings if f["severity"] == "MEDIUM"]
    if high:
        verdict, conf = "[CRITICAL] POSSIBLE CLICKFIX / MALICIOUS PAGE", "High" if len(high) > 1 or steps >= 2 else "Medium"
    elif len(med) >= 2:
        verdict, conf = "[WARNING] SUSPICIOUS PAGE PATTERNS", "Medium"
    elif med:
        verdict, conf = "[WARNING] SUSPICIOUS PAGE PATTERN", "Low"
    else:
        verdict, conf = "[INFO] NO INDICATORS FOUND (static view only)", "Low" if js_note else "Medium"
    reasons = [f"{f['severity']}: {f['text']}" for f in sorted(findings, key=lambda f: ("HIGH", "MEDIUM", "INFO").index(f["severity"]))]
    if js_note:
        reasons.append("NOTE: " + js_note)
    sandbox = {"page.html": {"type": "TEXT", "lang": "html", "size": len(html), "content": html[:ac.DISPLAY_CHARS],
                             "suspicious_lines": [f["text"] for f in findings if f["severity"] != "INFO"][:20], "hits": []}}
    if script_text.strip():
        sandbox["inline-scripts.js"] = {"type": "TEXT", "lang": "javascript", "size": len(script_text),
                                        "content": script_text[:ac.DISPLAY_CHARS], "suspicious_lines": [], "hits": []}
    return {"verdict": verdict, "confidence": conf, "verdict_reasons": reasons, "findings": findings,
            "score": summary["malware_score"], "rules": summary, "title": p.title, "page_host": page_host,
            "stats": {"visible_chars": len(visible), "hidden_chars": len(hidden), "scripts": len(p.scripts),
                      "external_scripts": len(p.script_src), "iframes": len(p.iframes), "links": len(p.links)},
            "iocs": ioc_list, "js_rendered_warning": js_note, "sandbox_files": sandbox}


def scan_url(url: str, progress: Optional[Callable[[str], None]] = None) -> Dict:
    say = progress or (lambda m: None)
    t0 = time.perf_counter()
    u = (url or "").strip()
    if "://" not in u:
        u = "https://" + u
    try:
        say("Fetching page ...")
        html, final, ct, status = fetch_page(u)
    except ac.UnsafeURL as e:
        return {"error": f"Blocked: {e}"}
    except ValueError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": f"{type(e).__name__}: {str(e)[:150]}"}
    say("Analysing page ...")
    rep = analyze_html(html, final)
    rep.update({"url": u, "final_url": final, "content_type": ct, "provider": "web", "mode": "static",
                "timings": {"total": round(time.perf_counter() - t0, 2)}})
    return rep
