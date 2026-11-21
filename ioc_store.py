# ============================================
# LICENSE & SOURCE
# ============================================
# Licensed under AGPL3 + ESOL v2.1
# Source: https://github.com/NemesisCyberForce/bulkScam
# ============================================
"""Private case log for scam networks (IOC store) + cluster matching.

Design rules (decided together, keep them):
  * OFF unless IOC_STORE_PATH is set. Private by default. Nothing is published from here.
  * Every case starts as human_status="unreviewed" (quarantine). Export only returns "confirmed" cases.
  * Verdicts are indications, not findings of fraud. label_source says where a label came from
    (rule / llm / osv / malwarebazaar / human) so pseudo-labels are never mistaken for ground truth.
  * No secrets, no raw e-mails (hash only), no file contents - only IOCs, hashes, rule ids and the verdict.
  * It cannot know the scammer's real IPs/proxies; it only stores what the scanned content itself contains.
Storage: append-only JSONL (latest line per case_id wins). The Space disk is ephemeral - copy the file out
or sync it to a PRIVATE dataset repo yourself.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
from typing import Dict, List, Optional

STATUSES = ("unreviewed", "confirmed", "false_positive")
# What may create an edge between two cases. filehost/url/domain-of-big-hosts never do.
STRONG_TYPES = {"telegram", "discord_webhook", "telegram_bot", "wallet_eth", "wallet_btc", "wallet_xmr", "wallet_trx",
                "email_hash", "archive_sha256"}
MEDIUM_TYPES = {"ip", "domain"}
_MASCHE = [
    ("scam funnel", "scam_funnel"), ("lead-magnet", "scam_funnel"), ("scam-typical", "scam_claims"),
    ("jailbreak", "jailbreak_wrapper"), ("clickfix", "clickfix"), ("malware", "malware"), ("critical", "malware_or_loader"),
]
_lock = threading.Lock()


def _masche(report: Dict) -> str:
    v = (report.get("verdict") or "").lower()
    for key, name in _MASCHE:
        if key in v:
            return name
    if report.get("osv", {}).get("malicious"):
        return "malicious_package"
    if any("password" in str(r).lower() for r in report.get("verdict_reasons", [])):
        return "password_archive"
    return "other" if "[ok]" not in v and "[info]" not in v else "none"


def _label_source(report: Dict) -> List[str]:
    src = ["rule"]
    if report.get("llm_results"):
        src.append("llm")
    if report.get("osv", {}).get("malicious"):
        src.append("osv")
    if any((a.get("malwarebazaar") or {}).get("found") for a in report.get("artifacts", [])):
        src.append("malwarebazaar")
    return src


def case_id(provider: str, slug: str) -> str:
    return hashlib.sha256(f"{provider}|{slug.lower()}".encode()).hexdigest()[:12]


def report_hint(provider: str) -> str:
    return {"github": "https://github.com/contact/report-abuse"}.get(provider, "")


def make_case(report: Dict, url: str) -> Optional[Dict]:
    """Report -> case record. Returns None for reports without a usable verdict or without any IOC."""
    if not report or "error" in report or not report.get("verdict"):
        return None
    keep = [{"type": i["type"], "value": i["value"], "strength": i["strength"], "where": i.get("where", [])[:3]}
            for i in report.get("iocs", []) if i["type"] != "url"][:150]
    slug = report.get("repo_info") or report.get("final_url") or url
    prov = report.get("provider", "github")
    now = int(time.time())
    return {
        "case_id": case_id(prov, re.sub(r"@.*$", "", slug)),
        "url": url, "provider": prov, "target": re.sub(r"@.*$", "", slug)[:200],
        "first_seen": now, "last_seen": now, "verdict": report["verdict"], "confidence": report.get("confidence"),
        "masche": _masche(report), "iocs": keep,
        "evidence_hash": hashlib.sha256("\n".join(sorted(f"{i['type']}:{i['value']}" for i in keep)).encode()).hexdigest()[:16],
        "label_source": _label_source(report), "human_status": "unreviewed", "report_hint": report_hint(prov),
    }


class CaseStore:
    def __init__(self, path: str):
        self.path = path

    @classmethod
    def from_env(cls) -> Optional["CaseStore"]:
        p = os.environ.get("IOC_STORE_PATH", "").strip()
        return cls(p) if p else None

    # ---- io
    def _load(self) -> Dict[str, Dict]:
        cases: Dict[str, Dict] = {}
        try:
            with open(self.path, encoding="utf-8") as f:
                for line in f:
                    try:
                        c = json.loads(line)
                        cases[c["case_id"]] = c
                    except Exception:
                        continue
        except FileNotFoundError:
            pass
        return cases

    def _append(self, case: Dict) -> None:
        d = os.path.dirname(self.path)
        if d:
            os.makedirs(d, exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(case, ensure_ascii=False) + "\n")

    # ---- api
    def add(self, report: Dict, url: str) -> Optional[Dict]:
        case = make_case(report, url)
        if not case:
            return None
        with _lock:
            old = self._load().get(case["case_id"])
            if old:  # keep first_seen and a human decision; refresh the rest
                case["first_seen"] = old.get("first_seen", case["first_seen"])
                case["human_status"] = old.get("human_status", "unreviewed")
                if "human" in old.get("label_source", []) and "human" not in case["label_source"]:
                    case["label_source"] = case["label_source"] + ["human"]
                seen = {(i["type"], i["value"]) for i in case["iocs"]}
                case["iocs"] += [i for i in old.get("iocs", []) if (i["type"], i["value"]) not in seen][:50]
            self._append(case)
        return case

    def cases(self) -> List[Dict]:
        return sorted(self._load().values(), key=lambda c: -c.get("last_seen", 0))

    def set_status(self, cid: str, status: str) -> bool:
        if status not in STATUSES:
            return False
        with _lock:
            c = self._load().get(cid)
            if not c:
                return False
            c["human_status"] = status
            if status == "confirmed" and "human" not in c["label_source"]:
                c["label_source"] = c["label_source"] + ["human"]
            self._append(c)
        return True

    def export_confirmed(self) -> List[Dict]:
        """Public-safe view: confirmed cases only, strong/medium IOCs only, no free text."""
        out = []
        for c in self.cases():
            if c.get("human_status") != "confirmed":
                continue
            out.append({"case_id": c["case_id"], "provider": c["provider"], "masche": c["masche"],
                        "first_seen": c["first_seen"], "evidence_hash": c["evidence_hash"],
                        "iocs": [{"type": i["type"], "value": i["value"]} for i in c["iocs"]
                                 if i["strength"] in ("strong", "medium") and i["type"] not in ("archive_password",)]})
        return out

    def clusters(self, include_false_positives: bool = False) -> List[Dict]:
        """Connected components: two cases are linked by >=1 shared STRONG ioc or >=2 shared MEDIUM iocs."""
        cs = [c for c in self.cases() if include_false_positives or c.get("human_status") != "false_positive"]
        parent = {c["case_id"]: c["case_id"] for c in cs}

        def find(x):
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x
        by_val: Dict[tuple, List[str]] = {}
        for c in cs:
            for i in c["iocs"]:
                if i["type"] in STRONG_TYPES or i["type"] in MEDIUM_TYPES:
                    by_val.setdefault((i["type"], i["value"]), []).append(c["case_id"])
        pair_medium: Dict[tuple, int] = {}
        shared: Dict[tuple, List[tuple]] = {}
        for (typ, val), ids in by_val.items():
            ids = sorted(set(ids))
            if len(ids) < 2 or len(ids) > 200:  # a value shared by hundreds of cases is a CDN/common host, not a link
                continue
            for a in range(len(ids)):
                for b in range(a + 1, len(ids)):
                    key = (ids[a], ids[b])
                    shared.setdefault(key, []).append((typ, val))
                    if typ in MEDIUM_TYPES:
                        pair_medium[key] = pair_medium.get(key, 0) + 1
                    else:
                        pair_medium[key] = pair_medium.get(key, 0) + 100
        for (a, b), score in pair_medium.items():
            if score >= 100 or score >= 2:
                parent[find(a)] = find(b)
        groups: Dict[str, List[str]] = {}
        for c in cs:
            groups.setdefault(find(c["case_id"]), []).append(c["case_id"])
        index = {c["case_id"]: c for c in cs}
        out = []
        for ids in groups.values():
            if len(ids) < 2:
                continue
            links = sorted({f"{t}:{v}" for (a, b), vals in shared.items() if a in ids and b in ids for t, v in vals})
            out.append({"cases": sorted(ids), "targets": [index[i]["target"] for i in sorted(ids)],
                        "shared_iocs": links[:30], "size": len(ids)})
        return sorted(out, key=lambda g: -g["size"])
