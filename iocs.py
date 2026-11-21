# ============================================
# LICENSE & SOURCE
# ============================================
# Licensed under AGPL3 + ESOL v2.1
# Source: https://github.com/NemesisCyberForce/bulkScam
# ============================================
"""IOC extraction (indicators of compromise) from text that was already read statically.

What this CAN see: what is written in files/pages (domains, IPs, Telegram handles, Discord webhooks, bot ids,
wallets, hashed e-mails, archive passwords). What it can NOT see: the real IPs/proxies a scammer used to upload.
Secrets are never stored: webhook tokens/bot tokens are reduced to their public id, e-mails to a short hash.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
from typing import Dict, Iterable, List, Optional
from urllib.parse import urlparse

STRONG = {"telegram", "discord_webhook", "telegram_bot", "wallet_eth", "wallet_btc", "wallet_xmr", "wallet_trx",
          "email_hash", "archive_sha256"}
MEDIUM = {"ip", "domain", "archive_password"}
WEAK = {"filehost", "url", "ip_list"}
IP_LIST_MIN = 15   # a file with more distinct IPs than this is a list (proxies, blocklists, data), not infrastructure
PUBLIC_DNS = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220", "4.2.2.2"}

FILEHOSTS = ("mega.nz", "mega.io", "mediafire.com", "gofile.io", "pixeldrain.com", "anonfiles.com", "1fichier.com",
             "transfer.sh", "catbox.moe", "file.io", "wetransfer.com", "sendspace.com", "dropbox.com", "drive.google.com",
             "docs.google.com", "disk.yandex.ru", "disk.yandex.com", "workupload.com", "krakenfiles.com", "temp.sh",
             "bayfiles.com", "zippyshare.com", "uploadhaven.com", "send.cm", "ufile.io", "dosya.co")
BENIGN = ("github.com", "githubusercontent.com", "gitlab.com", "huggingface.co", "hf.co", "pypi.org", "pythonhosted.org",
          "python.org", "npmjs.com", "npmjs.org", "w3.org", "google.com", "googleapis.com", "gstatic.com", "microsoft.com",
          "apache.org", "mozilla.org", "wikipedia.org", "openai.com", "anthropic.com", "readthedocs.io", "stackoverflow.com",
          "creativecommons.org", "opensource.org", "gnu.org", "pytorch.org", "tensorflow.org", "docker.com", "nodejs.org",
          "shields.io", "img.shields.io", "badge.fury.io", "twitter.com", "x.com", "youtube.com", "youtu.be", "linkedin.com",
          "example.com", "example.org", "localhost", "ngrok.com", "arxiv.org", "doi.org", "medium.com", "reddit.com",
          "discord.com", "discord.gg", "telegram.org", "t.me", "paypal.com", "buymeacoffee.com", "ko-fi.com", "patreon.com",
          "bitbucket.org", "codeberg.org", "sr.ht", "pypa.io", "python.org", "pip.pypa.io", "nuget.org", "rubygems.org",
          "crates.io", "golang.org", "go.dev", "sourceforge.net", "gnu.org", "ubuntu.com", "debian.org", "discordapp.com",
          "discordapp.net", "discord.gift", "roblox.com", "ipinfo.io", "ipify.org", "ifconfig.me", "icanhazip.com")
_CODE_SUFFIX = (".py", ".pyw", ".js", ".mjs", ".ts", ".tsx", ".jsx", ".sh", ".bash", ".ps1", ".bat", ".cmd", ".vbs", ".json", ".yml",
                ".yaml", ".toml", ".ini", ".cfg", ".c", ".h", ".cpp", ".cs", ".java", ".go", ".rs", ".php", ".rb", ".lua", ".pyc")
_EMAIL_SKIP = ("example.com", "example.org", "users.noreply.github.com", "noreply.github.com", "localhost")

_URL = re.compile(r"https?://[^\s\"'<>\\)\]}]{4,300}", re.I)
_TG = re.compile(r"(?i)\b(?:t\.me|telegram\.(?:me|dog))/(?!joinchat\b|\+)(@?[A-Za-z][A-Za-z0-9_]{3,31})\b")
_TG_AT = re.compile(r"(?i)\btelegram\b[^\n]{0,40}?@([A-Za-z][A-Za-z0-9_]{4,31})\b")
_DISCORD = re.compile(r"(?i)discord(?:app)?\.com/api/webhooks/(\d{3,22})/[A-Za-z0-9_-]{3,}")
_BOT = re.compile(r"\b(\d{8,11}):[A-Za-z0-9_-]{35}\b")
_ETH = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
_BTC_BECH = re.compile(r"\bbc1[ac-hj-np-z02-9]{25,59}\b")
_BTC_LEG = re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")
_XMR = re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")
_TRX = re.compile(r"\bT[1-9A-HJ-NP-Za-km-z]{33}\b")
_WALLET_CTX = re.compile(r"(?i)wallet|address|donat|btc|bitcoin|usdt|trc20|erc20|tron|monero|xmr|send|payment|pay\b|crypto")
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]{2,64}@([A-Za-z0-9.-]{3,100}\.[A-Za-z]{2,24})\b")
_IP = re.compile(r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?::(\d{2,5}))?(?![\d.])")
_IP_CTX = re.compile(r"(?i)\b(?:ip|host|server|c2|connect|socket|proxy|beacon|lhost|callback|remote)\b")
_BARE_DOMAIN = re.compile(r"(?i)\b([a-z0-9][a-z0-9-]{1,40}(?:\.[a-z0-9-]{1,40}){0,3}\.(?:com|net|org|io|xyz|top|club|site|online|shop|app|dev|ru|cn|tk|ml|ga|cf|gq|su|pw|cc|ws|me|to|ly|gg|sh)\b)")


def _public_ip(s: str) -> bool:
    try:
        return ipaddress.ip_address(s).is_global
    except ValueError:
        return False


def _host_of(url: str) -> Optional[str]:
    try:
        h = (urlparse(url.rstrip(".,;:!?)")).hostname or "").lower().rstrip(".")
        return h or None
    except ValueError:
        return None


def _is_benign(host: str) -> bool:
    return any(host == b or host.endswith("." + b) for b in BENIGN)


def _is_filehost(host: str) -> bool:
    return any(host == f or host.endswith("." + f) for f in FILEHOSTS)


class _Acc:
    def __init__(self, cap: int = 300):
        self.items: Dict[tuple, dict] = {}
        self.cap = cap

    def add(self, typ: str, value: str, where: str) -> None:
        key = (typ, value)
        it = self.items.get(key)
        if it is None:
            if len(self.items) >= self.cap:
                return
            strength = "strong" if typ in STRONG else "medium" if typ in MEDIUM else "weak"
            it = self.items[key] = {"type": typ, "value": value, "strength": strength, "where": [], "count": 0}
        it["count"] += 1
        if where not in it["where"] and len(it["where"]) < 5:
            it["where"].append(where)


def extract(texts: Dict[str, str], archive_passwords: Optional[Iterable[bytes]] = None,
            archive_sha256: Optional[Iterable[str]] = None, max_chars: int = 1_500_000) -> List[dict]:
    """texts: {path: text}. Returns [{type, value, strength, where[], count}] sorted strong -> weak."""
    acc = _Acc()
    for path, text in texts.items():
        t = (text or "")[:max_chars]
        path_ips: set = set()
        for m in _URL.finditer(t):
            url = m.group(0).rstrip(".,;:!?'\"")
            host = _host_of(url)
            if not host:
                continue
            if _is_filehost(host):
                acc.add("filehost", host, path)
            elif not _is_benign(host):
                try:
                    ipaddress.ip_address(host)
                    if _public_ip(host) and host not in PUBLIC_DNS:
                        path_ips.add(host)
                except ValueError:
                    acc.add("domain", host, path)
                acc.add("url", re.sub(r"(?i)^http", "hxxp", url)[:200], path)
        for m in _TG.finditer(t):
            acc.add("telegram", m.group(1).lstrip("@").lower(), path)
        for m in _TG_AT.finditer(t):
            if m.group(1).lower() not in ("username", "channel", "yourname", "handle"):
                acc.add("telegram", m.group(1).lower(), path)
        for m in _DISCORD.finditer(t):
            acc.add("discord_webhook", f"webhook-id:{m.group(1)}", path)
        for m in _BOT.finditer(t):
            acc.add("telegram_bot", f"bot-id:{m.group(1)}", path)
        for m in _ETH.finditer(t):
            if len(set(m.group(0)[2:].lower())) > 4:  # skip 0x000... / 0xaaaa... placeholders
                acc.add("wallet_eth", m.group(0).lower(), path)
        for m in _BTC_BECH.finditer(t):
            acc.add("wallet_btc", m.group(0), path)
        for m in _XMR.finditer(t):
            acc.add("wallet_xmr", m.group(0), path)
        for rx, typ in ((_BTC_LEG, "wallet_btc"), (_TRX, "wallet_trx")):  # false-positive prone: need context
            for m in rx.finditer(t):
                ctx = t[max(0, m.start() - 100): m.end() + 40]
                if _WALLET_CTX.search(ctx) and len(set(m.group(0))) > 10:
                    acc.add(typ, m.group(0), path)
        for m in _EMAIL.finditer(t):
            dom = m.group(1).lower()
            if dom.endswith(_EMAIL_SKIP) or _is_benign(dom):
                continue
            acc.add("email_hash", hashlib.sha256(m.group(0).lower().encode()).hexdigest()[:16], path)
            acc.add("domain", dom, path)
        for line in t.split("\n")[:20000]:
            if len(line) > 600:
                continue
            ctx_line = bool(_IP_CTX.search(line))
            for m in _IP.finditer(line):
                ip, port = m.group(1), m.group(2)
                if _public_ip(ip) and ip not in PUBLIC_DNS and (port or ctx_line):
                    path_ips.add(ip)
        if len(path_ips) > IP_LIST_MIN:   # proxy list / blocklist: one weak summary instead of hundreds of "IOCs"
            acc.add("ip_list", f"list of {len(path_ips)} IP addresses (proxy/blocklist/data file)", path)
        else:
            for ip in sorted(path_ips):
                acc.add("ip", ip, path)
        low = t.lower()
        # bare domains (no http://) only in prose files: in code 'self.org' / 'os.path' are attribute accesses, not hosts
        if not path.lower().endswith(_CODE_SUFFIX) and ("telegram" in low or "t.me" in low or "download" in low):
            for m in _BARE_DOMAIN.finditer(t[:200_000]):
                d = m.group(1).lower()
                if _is_benign(d):
                    continue
                if _is_filehost(d):
                    acc.add("filehost", d, path)
                elif "." in d and not d.endswith((".py", ".js", ".md", ".sh", ".io.js")) and d.count(".") <= 3:
                    acc.add("domain", d, path)
    for pw in archive_passwords or []:
        s = pw.decode("utf-8", "replace") if isinstance(pw, (bytes, bytearray)) else str(pw)
        if s:
            acc.add("archive_password", s[:64], "(README)")
    for h in archive_sha256 or []:
        acc.add("archive_sha256", str(h).lower(), "(artifact)")
    order = {"strong": 0, "medium": 1, "weak": 2}
    return sorted(acc.items.values(), key=lambda i: (order[i["strength"]], i["type"], i["value"]))
