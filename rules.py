# rules.py - EINE Regelquelle fuer Scorer UND Viewer (v3).
# Quellen: PoisonIvory-Patterns (nur repo-taugliche), analyzer_core, Berichte 2024-2026
# (Check Point/Stargazers Ghost Network, Cato/Unit42 zu WormGPT/KawaiiGPT, ClickFix-Berichte,
#  TrapDoor/Moika-Paketkampagnen). Keine Seiteneffekte, kein Netzwerk.
# Scannt IMMER den Volltext (Kuerzen nur fuer die Anzeige!). Jede Regel hat einen Literal-Vorfilter
# ("need"): die Regex laeuft nur, wenn eines der kleingeschriebenen Woerter im Text vorkommt.
from __future__ import annotations

import base64
import json
import re
import zlib
from bisect import bisect_right
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Dict, List, Optional

MAX_SCAN_CHARS = 8_000_000
MAX_HITS_PER_RULE = 5
MAX_DECODE_CANDIDATES = 200
MAX_DECODED_TOTAL = 4_000_000

CODE_EXT = {".py", ".pyw", ".ipynb", ".js", ".mjs", ".cjs", ".ts", ".sh", ".bash",
            ".ps1", ".bat", ".cmd", ".vbs", ".php"}
DOC_EXT = {".md", ".txt", ".rst", ".mdc"}
# Dateien, die KI-Coding-Assistenten automatisch lesen (TrapDoor-Kampagne: .cursorrules mit Exfil-Anweisungen)
AGENT_FILES = {".cursorrules", ".windsurfrules", ".clinerules", "agents.md", "claude.md", "gemini.md",
               "copilot-instructions.md", "mcp.json", ".mcp.json"}
SEV_WEIGHT = {"HIGH": 25, "MEDIUM": 10, "INFO": 0}

_STRIP = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff\U000e0000-\U000e007f]")
_BIDI = re.compile("[\u202a-\u202e\u2066-\u2069]")
# nur Zero-Width-Folgen zwischen ASCII-Zeichen (steganografisch); in Persisch/Devanagari/Emoji sind sie legitim
_ZWC = re.compile("(?<=[\x20-\x7e])[\u200b\u200c\u2060\u2062-\u2064\ufeff]+(?=[\x20-\x7e])")
_TAGS = re.compile("[\U000e0000-\U000e007f]+")
_CONCAT = re.compile(r"""(['"])[ \t]*\+[ \t]*\1""")  # 'ex'+'ec' -> 'exec' (Zeilen bleiben erhalten)
_NL = re.compile("\n")


def is_agent_file(name: str) -> bool:
    n = name.lower()
    return n in AGENT_FILES or n.endswith(".mdc")


@dataclass(frozen=True)
class Rule:
    id: str
    cat: str    # exfil exec stealer hook agent leak inject jailbreak claim wrapper ml helper
    sev: str    # HIGH | MEDIUM | INFO
    rx: re.Pattern
    scope: str  # any | code | doc | agent | <dateiname>
    need: tuple


def R(id, cat, sev, pat, scope="any", need=()):
    return Rule(id, cat, sev, re.compile(pat, re.M), scope, tuple(need))


RULES: List[Rule] = [
    # ======================= Exfiltration / C2 =======================================
    R("exfil_discord_webhook", "exfil", "HIGH", r"discord(?:app)?\.com/api/webhooks/\d+", need=("api/webhooks",)),
    R("exfil_telegram_bot", "exfil", "HIGH", r"api\.telegram\.org/bot", need=("api.telegram.org",)),
    R("exfil_ip_logger", "exfil", "HIGH",
      r"(?i:grabify\.link|iplogger\.(?:org|com)|\b2no\.co\b|\bblasze\.com\b|\bleancoding\.co\b|\byip\.su\b)",
      need=("grabify", "iplogger", "2no.co", "blasze", "leancoding", "yip.su")),
    R("exfil_slack_webhook", "exfil", "MEDIUM", r"hooks\.slack\.com/services/T[A-Z0-9]{6,}/B[A-Z0-9]{6,}",
      need=("hooks.slack.com",)),
    R("exfil_pastebin", "exfil", "MEDIUM", r"(?i:pastebin\.com/(?:raw|api)|paste\.ee/r/|hastebin\.com/raw|\bghostbin\b)",
      need=("pastebin", "paste.ee", "hastebin", "ghostbin")),
    R("exfil_requestbin", "exfil", "MEDIUM",
      r"(?i:requestbin|webhook\.site|pipedream\.net|interact\.sh|canarytokens\.com|\boast\.(?:pro|live|site|online|fun|me)\b)",
      need=("requestbin", "webhook.site", "pipedream", "interact.sh", "canarytokens", "oast.")),
    R("exfil_filedrop", "exfil", "MEDIUM",
      r"(?i:\btransfer\.sh\b|\b0x0\.st\b|catbox\.moe/user/api\.php|pixeldrain\.com/api|gofile\.io/(?:uploadfile|api)|\banonfiles\b)",
      need=("transfer.sh", "0x0.st", "catbox", "pixeldrain", "gofile", "anonfiles")),
    R("tunnel_ngrok", "exfil", "MEDIUM",
      r"(?i:\b[\w-]+\.ngrok(?:-free)?\.(?:io|app|dev)\b|trycloudflare\.com|\bserveo\.net\b|\blocalhost\.run\b|\bloca\.lt\b|\bbore\.pub\b)",
      need=("ngrok", "trycloudflare", "serveo", "localhost.run", "loca.lt", "bore.pub")),

    # ======================= Ausfuehrung / Obfuskation ===============================
    R("exec_decode", "exec", "HIGH",
      r"\b(?:exec|eval)\s*\([^\n]{0,200}?(?:b64decode|b32decode|a85decode|decompress|marshal\.loads|fromhex|codecs\.decode|\.decrypt\()",
      "code", ("exec", "eval")),
    R("exec_remote", "exec", "HIGH",
      r"\b(?:exec|eval|compile)\s*\(\s*(?:requests\.(?:get|post)|urllib\.request\.urlopen|urlopen|httpx\.get)\s*\(|\b(?:exec|eval)\s*\(\s*\w+\.(?:text|content)\b",
      "code", ("exec", "eval", "compile")),
    R("import_obf", "exec", "HIGH", r"__import__\(\s*['\"](?:base64|zlib|marshal|codecs)['\"]\s*\)", "code", ("__import__",)),
    R("reduce_payload", "exec", "HIGH",
      r"def\s+__reduce__\s*\([^)]*\)\s*:[\s\S]{0,200}?(?:os\.system|subprocess|\bexec\b|\beval\b)", "code", ("__reduce__",)),
    R("pyarmor", "exec", "MEDIUM", r"pyarmor_runtime|__pyarmor__", "code", ("pyarmor",)),
    R("js_obf", "exec", "MEDIUM", r"\b(?:var|let|const|function)\s+_0x[0-9a-f]{4,6}\b", "code", ("_0x",)),
    R("js_eval_atob", "exec", "HIGH",
      r"\b(?:eval|Function)\s*\(\s*(?:atob|Buffer\.from)\s*\(|\bnew\s+Function\s*\(\s*(?:atob|Buffer\.from)\s*\(",
      "code", ("atob", "buffer.from")),
    R("builtins_obf", "exec", "MEDIUM",
      r"getattr\(\s*__builtins__\s*,\s*['\"](?:exec|eval|__import__|compile)['\"]|__builtins__\s*\[\s*['\"](?:exec|eval)|globals\(\)\s*\[\s*['\"]__builtins__",
      "code", ("__builtins__",)),
    R("chr_chain", "exec", "MEDIUM", r"(?:chr\(\s*\d+\s*\)\s*\+\s*){5,}", "code", ("chr(",)),
    R("ctypes_shellcode", "exec", "HIGH",
      r"ctypes\.windll\.kernel32\.(?:VirtualAlloc|CreateThread|WriteProcessMemory|RtlMoveMemory|VirtualProtect)",
      "code", ("kernel32",)),
    R("os_system_dl", "exec", "HIGH", r"os\.system\s*\(\s*['\"](?:curl|wget|powershell)", "code", ("os.system",)),
    R("subprocess_ps", "exec", "HIGH", r"subprocess\.\w+\([^\n]{0,120}powershell", "code", ("powershell",)),
    R("fernet", "exec", "MEDIUM", r"from\s+cryptography\.fernet\s+import|cryptography\.fernet", "code", ("fernet",)),
    R("revshell_devtcp", "exec", "HIGH", r"/dev/tcp/\d{1,3}(?:\.\d{1,3}){3}/\d+", need=("/dev/tcp/",)),
    R("revshell_nc", "exec", "HIGH", r"\bnc(?:at)?\b[^\n]{0,40}\s-e\s+/bin/(?:ba)?sh|\bmkfifo\b[^\n]{0,80}\bnc\b",
      need=("nc", "mkfifo")),
    R("revshell_py", "exec", "HIGH",  # klassisch: stdin/stdout auf Socket umleiten (CGI-Server nutzen nur ein dup2)
      r"\bos\.dup2\s*\(\s*\w+\.fileno\(\)\s*,\s*0\s*\)[\s\S]{0,200}?\bos\.dup2\s*\(\s*\w+\.fileno\(\)\s*,\s*1\s*\)|\bpty\.spawn\s*\(\s*['\"](?:/bin/)?(?:ba)?sh['\"]",
      "code", ("dup2", "pty.spawn")),
    # Shell/PowerShell auch in READMEs (ClickFix/InstallFix: "fuehr diesen Befehl im Terminal aus")
    R("ps_encoded", "exec", "HIGH", r"(?i:powershell(?:\.exe)?\b[^\n]{0,80}\s-(?:e|enc|encodedcommand)\b)", need=("powershell",)),
    R("ps_iex_download", "exec", "HIGH",
      r"(?i:\b(?:iex|invoke-expression)\b\s*\(\s*(?:new-object\s+(?:system\.)?net\.webclient|(?:irm|iwr|invoke-restmethod|invoke-webrequest)\b)|\bnew-object\s+(?:system\.)?net\.webclient\s*\)?\s*\.\s*downloadstring\s*\()",
      need=("iex", "invoke-expression", "downloadstring")),
    R("ps_pipe_iex", "exec", "HIGH",
      r"(?i:\b(?:irm|iwr|invoke-restmethod|invoke-webrequest|curl|wget)\b[^\n|]{0,200}\|\s*(?:iex|invoke-expression)\b)",
      need=("iex", "invoke-expression")),
    R("b64_pipe", "exec", "HIGH",  # erst die Kette 'base64 -d | sh' ist verdaechtig (ein blosses 'base64 -d' ist alltaeglich)
      r"\|\s*base64\s+(?:-d|--decode)\b[^\n]{0,80}\|\s*(?:sudo\s+)?(?:(?:ba|z)?sh|python3?|perl|node|php)\b", need=("base64",)),
    R("curl_pipe_sh", "exec", "MEDIUM",
      r"(?i:\b(?:curl|wget)\b[^\n|]{0,200}\|\s*(?:sudo\s+)?(?:(?:ba|z)?sh|pwsh|powershell|cmd)\b)", need=("curl", "wget")),
    R("win_lolbin", "exec", "HIGH",
      r"(?i:certutil\s+-urlcache|bitsadmin\s+/transfer|mshta\s+https?:|regsvr32\s+/s\s+/n\s+/u\s+/i:|\bfinger\s+\S+@\S+|rundll32(?:\.exe)?\s+[^\n]{0,80}javascript:)",
      need=("certutil", "bitsadmin", "mshta", "regsvr32", "finger", "rundll32")),
    R("clickfix_winr", "exec", "HIGH",
      r"(?is:(?:\bwin(?:dows)?\s*(?:key\s*)?\+\s*r\b|\brun\s+dialog\b)[^\n]{0,160}\b(?:paste|ctrl\s*\+\s*v)\b)", need=("paste", "ctrl")),
    R("clickfix_verify", "exec", "MEDIUM",
      r"(?i:verify\s+(?:that\s+)?you(?:'re|\s+are)\s+(?:a\s+)?human|\bi(?:'m|\s+am)\s+not\s+a\s+robot\b)", need=("human", "robot")),
    R("clipboard_js_cmd", "exec", "HIGH",
      r"(?is:(?:execcommand\(\s*['\"]copy['\"]\s*\)|clipboard\.writetext\s*\()[\s\S]{0,300}?(?:powershell|mshta|cmd(?:\.exe)?\s*/[ck]|curl\s|rundll32|finger\s|wscript))",
      need=("execcommand", "writetext")),

    # ======================= Stealer-Ziele ==========================================
    R("steal_browser", "stealer", "MEDIUM",
      r"(?i:(?:Login Data|Web Data|Local State)['\"]|User Data[\\/]+(?:Default|Profile)|\blogins\.json\b|\bkey4\.db\b|\bcookies\.sqlite\b)",
      need=("login data", "web data", "local state", "user data", "logins.json", "key4.db", "cookies.sqlite")),
    R("steal_dpapi", "stealer", "HIGH", r"\bbrowser_cookie3\b|\bCryptUnprotectData\b|\bwin32crypt\b", "code",
      ("browser_cookie3", "cryptunprotectdata", "win32crypt")),
    R("steal_discord_store", "stealer", "HIGH", r"(?i:Local Storage[\\/]+leveldb)", need=("leveldb",)),
    R("discord_token_regex", "stealer", "HIGH",
      r"\[\\w-\]\{24(?:,\d+)?\}\\\.\[\\w-\]\{6\}\\\.\[\\w-\]\{(?:27|25,\d+|27,\d+)\}|mfa\\\.\[\\w-\]\{84\}", need=("{24", "mfa")),
    R("steal_wallet", "stealer", "HIGH",
      r"(?i:\b(?:Exodus|Electrum|Coinomi|Guarda|Atomic)[\\/]|nkbihfbeogaeaoehlefnkodbefgpgknn|\bwallet\.dat\b)",
      need=("exodus", "electrum", "coinomi", "guarda", "atomic", "nkbihfbeogaeaoehlefnkodbefgpgknn", "wallet.dat")),
    R("steal_secret_files", "stealer", "MEDIUM",
      r"\.ssh[\\/]+(?:id_|known_hosts|authorized_keys)|\.aws[\\/]+credentials|\.git-credentials|\.pypirc|\.npmrc|\.netrc|\.docker[\\/]+config\.json|\.kube[\\/]+config|\.config[\\/]+gh[\\/]+hosts\.yml|/etc/shadow",
      need=(".ssh", ".aws", ".git-credentials", ".pypirc", ".npmrc", ".netrc", ".docker", ".kube", "hosts.yml", "/etc/shadow")),
    R("seed_phrase", "stealer", "MEDIUM",
      r"(?i:\b(?:seed\s+phrase|recovery\s+phrase|secret\s+recovery|mnemonic\s+(?:phrase|words|code)|bip-?39)\b)",
      need=("phrase", "mnemonic", "bip")),
    R("imds_access", "stealer", "MEDIUM", r"169\.254\.169\.254|metadata\.google\.internal|/latest/meta-data/iam",
      need=("169.254", "metadata.google", "meta-data")),
    R("container_sock", "stealer", "MEDIUM", r"/var/run/docker\.sock|KUBERNETES_SERVICE_HOST", need=("docker.sock", "kubernetes_service_host")),
    R("keylogger", "stealer", "MEDIUM",
      r"\bfrom\s+pynput\s+import\s+keyboard\b|\bpynput\.keyboard\b|\bGetAsyncKeyState\b|\bSetWindowsHookEx\w*\b|\bkeyboard\.on_press\b",
      "code", ("pynput", "getasynckeystate", "setwindowshookex", "on_press")),

    # ======================= Install-/Import-Zeit-Hooks ==============================
    R("hook_setup_py", "hook", "HIGH",
      r"cmdclass\s*=\s*\{[\s\S]{0,600}?(?:os\.system|subprocess|urlopen|requests\.|\bexec\(|\beval\()", "setup.py", ("cmdclass",)),
    R("hook_npm_script", "hook", "HIGH",
      r"\"(?:pre|post)?install\"\s*:\s*\"[^\"]{0,200}(?:curl|wget|powershell|base64|eval|bash\s+-c)", "package.json", ("install",)),
    R("hook_init_py", "hook", "MEDIUM",  # TrapDoor: Ausfuehrung beim Import
      r"(?m)^(?:requests\.(?:get|post|put)|urllib\.request\.urlopen|urlopen|subprocess\.\w+|os\.system|os\.popen|exec|eval)\s*\(",
      "__init__.py", ("requests.", "urlopen", "subprocess", "os.system", "os.popen", "exec", "eval")),
    R("hook_npm_remote_dep", "hook", "MEDIUM",
      r"\"(?:dependencies|devDependencies|optionalDependencies)\"\s*:\s*\{[^}]{0,3000}?\"\s*:\s*\"(?:https?://|git\+https?://)",
      "package.json", ("http",)),

    # ======================= KI-Assistenten-Regeldateien (Prompt-Injection gegen Coding-Agents) ===
    R("agent_exfil", "agent", "HIGH",
      r"(?i)\b(?:send|post|upload|exfiltrate|forward|transmit)\b[^\n]{0,100}\b(?:\.env|credentials?|api[_ -]?keys?|secrets?|tokens?|ssh\s+keys?|id_rsa|private\s+keys?)\b[^\n]{0,100}\b(?:to|at|via)\b[^\n]{0,60}(?:https?://|webhook|server|endpoint)",
      "agent", ("send", "post", "upload", "exfiltrate", "forward", "transmit")),
    R("agent_stealth", "agent", "HIGH",
      r"(?i)\bwithout\s+(?:telling|informing|notifying|asking)\s+(?:the\s+)?user\b|\b(?:do\s+not|don't|never)\s+(?:tell|inform|notify)\s+(?:the\s+)?user\s+(?:about|that|of)\b[^\n]{0,60}\b(?:command|script|request|upload|send|network|key|token|credential|secret)|\bsilently\s+(?:run|execute|send|upload|exfiltrate|curl|post)\b",
      "agent", ("without", "never", "don't", "do not", "silently")),
    R("agent_run_cmd", "agent", "MEDIUM",
      r"(?i)\b(?:always|first|before\s+(?:any|every)\w*)\b[^\n]{0,40}\b(?:run|execute)\b[^\n]{0,80}\b(?:curl|wget|powershell|bash\s+-c|npm\s+i(?:nstall)?|pip\s+install|npx|uvx)\b",
      "agent", ("run", "execute")),

    # ======================= Leaks (Meldung, NICHT Malware-Score; Treffer werden geschwaerzt) =====
    R("leak_openai", "leak", "INFO", r"\bsk-(?:proj|svcacct)-[A-Za-z0-9_\-]{40,}|\bsk-[A-Za-z0-9]{48}\b", need=("sk-",)),
    R("leak_anthropic", "leak", "INFO", r"\bsk-ant-(?:api\d\d-)?[A-Za-z0-9_\-]{40,}", need=("sk-ant-",)),
    R("leak_github", "leak", "INFO", r"\b(?:ghp|gho|ghs)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{50,}",
      need=("ghp_", "gho_", "ghs_", "github_pat_")),
    R("leak_hf", "leak", "INFO", r"\bhf_[A-Za-z0-9]{34}\b", need=("hf_",)),
    R("leak_google", "leak", "INFO", r"\bAIza[0-9A-Za-z\-_]{35}\b", need=("aiza",)),
    R("leak_aws", "leak", "INFO", r"\bAKIA[0-9A-Z]{16}\b", need=("akia",)),
    R("leak_stripe", "leak", "INFO", r"\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}\b", need=("_live_",)),
    R("leak_slack", "leak", "INFO", r"\bxox[baprs]-[A-Za-z0-9-]{10,}", need=("xox",)),
    R("leak_npm", "leak", "INFO", r"\bnpm_[A-Za-z0-9]{36}\b", need=("npm_",)),
    R("leak_pypi", "leak", "INFO", r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}", need=("pypi-ag",)),
    R("leak_telegram_bot", "leak", "INFO", r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b", need=(":",)),
    R("leak_discord", "leak", "INFO", r"\b[MNO][A-Za-z\d_-]{23,25}\.[\w-]{6}\.[\w-]{27,38}\b"),

    # ======================= Jailbreak-Persona-Prompts (Ziel: LLM HINTER dem Wrapper) ============
    R("jb_ignore_instructions", "jailbreak", "INFO",
      r"(?i:\bignore\s+(?:all\s+)?(?:the\s+)?(?:(?:previous|prior|above|earlier)\s+(?:instructions?|prompts?|rules|(?:content\s+)?polic(?:y|ies))|instructions\b))",
      need=("ignore",)),
    R("jb_unfiltered_persona", "jailbreak", "INFO",
      r"(?i:\b(?:unfiltered|amoral|unrestricted)\b[^\n]{0,60}\b(?:ai|chatbot|assistant|persona|model|hacker)\b)",
      need=("unfiltered", "amoral", "unrestricted")),
    R("jb_no_ethics", "jailbreak", "INFO",
      r"(?i:\b(?:any|no|without)\s+(?:ethical|moral|legal)(?:\s+or\s+(?:ethical|moral|legal))?\s+(?:guidelines|restrictions|boundaries|rules|limits)\b)",
      need=("ethical", "moral", "legal")),
    R("jb_never_refuse", "jailbreak", "INFO",
      r"(?i:\bnever\s+(?:refuse|apologi[sz]e)\b|\bnever\s+(?:tell|say)\b[^\n]{0,40}\b(?:can'?t|cannot)\b)", need=("never",)),
    R("jb_stay_in_character", "jailbreak", "INFO",
      r"(?i:\b(?:stay|remain)\s+in\s+character\b|\bfictional\s+(?:environment|character)\b)", need=("character", "fictional")),
    R("jb_break_free", "jailbreak", "INFO",
      r"(?i:\bbr(?:oken|eak)\s+free\s+(?:of|from)\s+(?:the\s+)?(?:typical\s+)?confines\b|\bdo\s+not\s+have\s+to\s+abide\s+by\b)",
      need=("free", "abide")),
    R("jb_dan", "jailbreak", "INFO",
      r"\bDAN\s+(?:mode|prompt|jailbreak)\b|\b(?:act\s+as|you\s+are(?:\s+now)?)\s+DAN\b|(?i:do\s+anything\s+now)", need=("dan", "anything now")),
    R("jb_reveal", "jailbreak", "INFO",
      r"(?i:\b(?:reveal|show|print)\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions)\b)", need=("prompt", "instructions")),

    # ======================= Injection gegen DEINEN Pruefer =============================
    R("inj_labels", "inject", "MEDIUM", r"\b(?:REAL_TRAINING|API_WRAPPER|MALWARE_STEALER|JAILBREAK_WRAPPER)\b",
      need=("real_training", "api_wrapper", "malware_stealer", "jailbreak_wrapper")),
    R("inj_auditor_msg", "inject", "MEDIUM",
      r"(?i:\b(?:attention|note\s+to|message\s+(?:for|to))\s+(?:the\s+)?(?:ai|llm|language\s+model|(?:code|security)\s+(?:reviewer|auditor|scanner|analy[sz]er)|classifier|auditor|scanner)\b|\binstructions?\s+(?:for|to)\s+(?:the\s+)?(?:code\s+|security\s+)?(?:reviewer|auditor|scanner|analy[sz]er|classifier)\b)",
      need=("attention", "note to", "message", "instruction")),
    R("inj_auditor_verdict", "inject", "MEDIUM",
      r"(?i:\b(?:mark|classify|label|report|rate|treat)\s+(?:this|the)\s+(?:repo(?:sitory)?|code|file|project)\s+as\s+(?:safe|benign|legit(?:imate)?|clean|harmless|trusted)\b|\bdo\s+not\s+flag\s+(?:this|it)\b)",
      need=("mark", "classify", "label", "report", "rate", "treat", "flag")),

    # ======================= Wrapper-Indikatoren (INFO, kein Risiko) ====================
    R("api_openai", "wrapper", "INFO", r"api\.openai\.com|\bimport\s+openai\b|\bfrom\s+openai\s+import\b", "code", ("openai",)),
    R("api_anthropic", "wrapper", "INFO", r"api\.anthropic\.com|\bimport\s+anthropic\b|\bfrom\s+anthropic\s+import\b", "code", ("anthropic",)),
    R("api_google", "wrapper", "INFO",
      r"generativelanguage\.googleapis\.com|google\.generativeai|\bfrom\s+google\s+import\s+genai\b", "code",
      ("generativelanguage", "generativeai", "genai")),
    R("api_other", "wrapper", "INFO",
      r"api\.mistral\.ai|api\.groq\.com|api\.cohere\.(?:ai|com)|openrouter\.ai/api|api\.together\.(?:xyz|ai)|api\.x\.ai|api\.deepseek\.com|api\.perplexity\.ai|api\.fireworks\.ai|integrate\.api\.nvidia\.com"
      r"|api-inference\.huggingface\.co|router\.huggingface\.co|\bInferenceClient\b|\bimport\s+replicate\b", "code",
      ("mistral", "groq", "cohere", "openrouter", "together", "api.x.ai", "deepseek", "perplexity", "fireworks", "nvidia", "huggingface", "inferenceclient", "replicate")),
    R("api_framework", "wrapper", "INFO", r"\b(?:litellm|langchain_openai|langchain_anthropic|langchain_google_genai|pydantic_ai)\b", "code",
      ("litellm", "langchain_", "pydantic_ai")),
    R("api_chat_endpoint", "wrapper", "INFO", r"requests\.post\s*\([^)]{0,200}/(?:v1/)?(?:chat/)?completions", "code", ("completions",)),

    # ======================= Echtes Training (INFO; zaehlt nur bei >=3 verschiedenen Treffern) ===
    R("ml_optim", "ml", "INFO", r"\btorch\.optim\b|\btf\.keras\.optimizers\b|\boptax\.\w+|\bAdamW?\(", "code",
      ("torch.optim", "keras.optimizers", "optax", "adam")),
    R("ml_backward", "ml", "INFO", r"\.backward\(\)|\baccelerator\.backward\b|\bvalue_and_grad\b|\bjax\.grad\b|\btf\.GradientTape\b", "code",
      (".backward", "value_and_grad", "jax.grad", "gradienttape")),
    R("ml_step", "ml", "INFO", r"\b(?:opt|optim|optimizer|optimiser)\w*\.step\(|\b\w*optimizer\.step\(|\bscaler\.step\(|\bscheduler\.step\(",
      "code", (".step(",)),
    R("ml_zero_grad", "ml", "INFO", r"\.zero_grad\(", "code", ("zero_grad",)),
    R("ml_loss", "ml", "INFO", r"\bcross_entropy\b|\bCrossEntropyLoss\b|\bMSELoss\b|\bloss_fn\b|\bcriterion\s*[(=]", "code",
      ("cross_entropy", "crossentropyloss", "mseloss", "loss_fn", "criterion")),
    R("ml_dataloader", "ml", "INFO", r"\bDataLoader\(|\btf\.data\.Dataset\b|\bload_dataset\(", "code", ("dataloader", "tf.data", "load_dataset")),
    R("ml_train_mode", "ml", "INFO", r"\.train\(\)|\bmodel\.fit\(|\btrainer\.train\(", "code", (".train(", ".fit(")),
    R("ml_trainer", "ml", "INFO",
      r"from\s+transformers\s+import[^\n]*\bTrainer\b|\b(?:SFT|DPO|PPO|GRPO)Trainer\b|\bpl\.Trainer\b|\baccelerator\.prepare\(|\bDeepSpeed\b|\bdeepspeed\b",
      "code", ("trainer", "accelerator.prepare", "deepspeed")),
    R("ml_module", "ml", "INFO", r"class\s+\w+\(\s*(?:torch\.)?nn\.Module\s*\)", "code", ("nn.module",)),

    # ======================= Hilfs-Signale fuer Kombinationen (INFO) ====================
    R("net_send", "helper", "INFO",
      r"\brequests\.(?:post|put)\s*\(|\bhttpx\.post\s*\(|\burlopen\s*\(|\bsocket\.socket\s*\(|\bXMLHttpRequest\b|\baxios\.(?:post|put)\s*\(|\bhttps?\.request\s*\(|\bfetch\s*\(\s*[`'\"]https?://|\bnavigator\.sendBeacon\b",
      "code", ("requests.", "httpx.", "urlopen", "socket", "xmlhttprequest", "axios", "http.request", "https.request", "fetch(", "sendbeacon")),
    R("walk_files", "helper", "INFO", r"\bos\.walk\s*\(|\.rglob\s*\(", "code", ("os.walk", "rglob")),
    R("env_dump", "helper", "INFO",  # nur Serialisierung/Ausgabe der Umgebung, nicht os.environ.copy() (extrem haeufig, legitim)
      r"json\.dumps\(\s*(?:dict\(\s*)?os\.environ|\b(?:str|repr)\(\s*os\.environ\s*\)|/proc/self/environ|\bprintenv\b|JSON\.stringify\(\s*process\.env|\{\s*\.\.\.process\.env\s*\}|\$\(\s*env\s*\)|\benv\s*\|\s*(?:base64|curl|nc)\b",
      "exec", ("environ", "printenv", "process.env", "env)", "env |", "env|")),
    R("net_send_sh", "helper", "INFO",
      r"\bcurl\b[^\n]{0,200}\s(?:-d|--data(?:-binary|-raw|-urlencode)?|-F|--form|--upload-file|-T)\b|\bwget\b[^\n]{0,100}--post-(?:data|file)\b|\bnc\s+\S+\s+\d{2,5}\b",
      "exec", ("curl", "wget", "nc ")),
    R("ip_lookup", "helper", "INFO",
      r"(?i:api\.ipify\.org|\bipinfo\.io\b|ip-api\.com|checkip\.amazonaws\.com|icanhazip\.com|ifconfig\.me|\bident\.me\b|ipecho\.net)",
      "code", ("ipify", "ipinfo", "ip-api", "checkip", "icanhazip", "ifconfig.me", "ident.me", "ipecho")),
    R("sysinfo", "helper", "INFO", r"getpass\.getuser\(\)|platform\.node\(\)|socket\.gethostname\(\)|os\.getlogin\(\)", "code",
      ("getuser", "platform.node", "gethostname", "getlogin")),
    R("clip_py", "helper", "INFO", r"\bpyperclip\.(?:paste|copy)\b|\bwin32clipboard\b", "code", ("pyperclip", "win32clipboard")),
    R("crypto_addr", "helper", "INFO", r"\bbc1[a-z0-9]{25,59}\b|\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b|\b0x[a-fA-F0-9]{40}\b", "code"),
    R("registry_publish", "helper", "INFO", r"upload\.pypi\.org/legacy|\btwine\s+upload\b|\bnpm\s+publish\b|registry\.npmjs\.org/-/npm/v1/user",
      "code", ("pypi.org/legacy", "twine", "npm publish", "npmjs.org")),
    R("uses_decode", "helper", "INFO", r"\b(?:b64decode|b32decode|a85decode|zlib\.decompress|marshal\.loads|fromhex|codecs\.decode)\b", "code",
      ("b64decode", "b32decode", "a85decode", "decompress", "marshal", "fromhex", "codecs.decode")),
    R("uses_exec", "helper", "INFO", r"\b(?:exec|eval)\s*\(", "code", ("exec", "eval")),

    # ======================= Behauptungen/Signale nur in Doku (Gegencheck gegen Code im Verdikt) ====
    R("claim_uncensored", "claim", "INFO",
      r"(?i:\b(?:uncensored|unfiltered|jailbr(?:eak|oken)|no\s+(?:restrictions|limits|filters|guardrails|censorship)|without\s+(?:restrictions|limits|limitations|censorship)|bypass(?:es|ing)?\s+(?:conventional\s+|all\s+)?(?:ai\s+|safety\s+|content\s+)?(?:limitations|restrictions|filters|guardrails))\b|\bunrestricted\b[^\n.]{0,40}\b(?:ai|llm|chat(?:bot)?|conversations?|model|gpt)\b)",
      "doc", ("uncensored", "unfiltered", "unrestricted", "jailbr", "restrictions", "limits", "limitations", "filters", "guardrails", "censorship")),
    R("claim_evilgpt", "claim", "INFO", r"(?i:\b(?:worm|fraud|evil|dark|xxx|wolf|ghost|hacker|kawaii)gpt\b)", "doc", ("gpt",)),
    R("claim_own_model", "claim", "INFO",
      r"(?i:\b(?:our|my|proprietary|private(?:ly[- ]developed)?)\s+(?:[\w-]+\s+){0,2}(?:llm|model)\b|\bfine-?tuned\s+(?:large\s+language\s+)?(?:on|model|llm)\b|\btrained\s+from\s+scratch\b|\b(?:supervised\s+fine-?tuning|reinforcement\s+learning|rlhf)\b)",
      "doc", ("our", "my", "proprietary", "private", "fine-tun", "finetun", "scratch", "supervised", "reinforcement", "rlhf")),
    R("claim_private_offer", "claim", "INFO",
      r"(?i:(?<![\w-])(?:private|exclusive|premium|paid)\s+(?:model|version|access|service|edition|plan|offering)\b|\bpricing\b|\bcontact\s+(?:our\s+team|us|me)\s+(?:via|on|through)\s+(?:telegram|whatsapp|discord)\b|\bDM\s+(?:me|us)\b)",
      "doc", ("private", "exclusive", "premium", "paid", "pricing", "contact", "dm")),
    R("claim_disclosure", "claim", "INFO",
      r"(?i:\bwrapper\b|\buses?\s+(?:the\s+)?(?:openai|anthropic|chatgpt|claude|gemini)\s+api\b|\bpowered\s+by\s+(?:openai|chatgpt|gpt|claude|gemini)\b|\brequires?\s+an?\s+(?:openai\s+)?api\s+key\b)",
      "doc", ("wrapper", "api", "powered")),
    R("claim_sales", "claim", "INFO",
      r"(?i:\b(?:lifetime\s+(?:access|license)|buy\s+now|keygen|cracked?|undetectable|fud|bypass(?:es)?\s+(?:antivirus|av|edr|defender)|price\s+list)\b|\b(?:sellix\.io|shoppy\.gg)\b)",
      "doc", ("lifetime", "buy now", "keygen", "crack", "undetectable", "fud", "bypass", "price list", "sellix", "shoppy")),
    R("claim_filehost", "claim", "INFO",
      r"(?i:\b(?:mega\.nz|mediafire\.com|gofile\.io|anonfiles|workupload\.com|pixeldrain\.com|bit\.ly|tinyurl\.com|cutt\.ly|rebrand\.ly|shorturl\.at|is\.gd|t\.ly|discord\.gg)\b|\bt\.me/[\w+]+|\btelegram\.me/[\w+]+)",
      "doc", ("mega.nz", "mediafire", "gofile", "anonfiles", "workupload", "pixeldrain", "bit.ly", "tinyurl", "cutt.ly", "rebrand.ly", "shorturl", "is.gd", "t.ly", "discord.gg", "t.me/", "telegram.me/")),
    R("claim_download_link", "claim", "INFO", r"(?i)https?://[^\s)\"'<>]+\.(?:exe|msi|scr|bat|ps1|vbs|jar|apk|zip|rar|7z)\b",
      "doc", (".exe", ".msi", ".scr", ".bat", ".ps1", ".vbs", ".jar", ".apk", ".zip", ".rar", ".7z")),
    R("claim_ip_url", "claim", "INFO",  # nur oeffentliche IP-Literale (nicht localhost/Privatnetz)
      r"https?://(?!(?:127|10|0)\.)(?!192\.168\.)(?!172\.(?:1[6-9]|2\d|3[01])\.)\d{1,3}(?:\.\d{1,3}){3}[:/]", "doc", ("http",)),
    R("claim_punycode", "claim", "INFO", r"(?i)https?://[^\s/]*xn--", "doc", ("xn--",)),
    R("claim_lure_theme", "claim", "INFO",
      r"(?i:\b(?:crack(?:ed)?|keygen|activator|aimbot|wallhack|executor|auto\s*clicker|wallet\s+drainer|sniper\s+bot|airdrop\s+(?:claimer|checker)|free\s+(?:robux|v-?bucks))\b)",
      "doc", ("crack", "keygen", "activator", "aimbot", "wallhack", "executor", "clicker", "drainer", "sniper", "airdrop", "robux", "bucks")),
]

ALL_NEEDLES = frozenset(w for r_ in RULES for w in r_.need)

# Kombinationen: jede Gruppe muss mindestens einen Treffer in DERSELBEN Datei haben.
_EXFIL_CH = {"exfil_discord_webhook", "exfil_telegram_bot", "exfil_pastebin", "exfil_requestbin", "exfil_ip_logger",
             "exfil_slack_webhook", "exfil_filedrop"}
_NET = _EXFIL_CH | {"net_send", "net_send_sh"}
_STEAL_STRONG = {"steal_browser", "steal_dpapi", "steal_discord_store", "discord_token_regex", "steal_wallet"}
_STEAL_WEAK = {"steal_secret_files", "seed_phrase", "imds_access"}
COMBOS = [
    ([_STEAL_STRONG, _NET], 40, "Stealer: Browser-/Wallet-/Token-Ziele + Netzwerk-Versand"),
    ([_STEAL_WEAK, _EXFIL_CH], 40, "Credential-Pfade/Seed-Phrasen + Exfiltrationskanal"),
    ([{"exec_decode", "js_eval_atob", "b64_pipe", "ps_encoded", "ps_iex_download", "ps_pipe_iex", "exec_remote"}, _NET],
     25, "Loader/Stager: Dekodieren+Ausfuehren + Netzwerk"),
    ([{"env_dump"}, _NET], 30, "Umgebungsvariablen werden nach aussen gesendet"),
    ([{"fernet"}, {"walk_files"}], 20, "Ransomware-aehnlich: Fernet + Dateisystem-Walk"),
    ([{"keylogger"}, _NET], 35, "Keylogger + Netzwerk-Versand"),
    ([{"clip_py"}, {"crypto_addr"}], 40, "Clipboard-Hijacker: Zwischenablage + Wallet-Adressen"),
    ([{"registry_publish"}, {"steal_secret_files"}], 10, "Registry-Tokens lesen + veroeffentlichen (ambivalent: legitim bei Publish-Tools)"),
    ([{"ip_lookup", "sysinfo"}, _EXFIL_CH], 25, "System-/IP-Recon + Exfiltrationskanal"),
    ([{"uses_decode"}, {"uses_exec"}], 15, "Dekodieren + dynamische Ausfuehrung in einer Datei"),
]


@dataclass
class Hit:
    rule: str
    cat: str
    sev: str
    line: int
    snippet: str


def _in_scope(rule: Rule, name: str, ext: str) -> bool:
    s = rule.scope
    if s == "any":
        return True
    if s == "code":
        return ext in CODE_EXT
    if s == "doc":
        return ext in DOC_EXT
    if s == "agent":
        return is_agent_file(name)
    if s == "exec":  # Code, CI-Workflows, Dockerfile - aber keine Doku (dort stehen harmlose curl-Beispiele)
        return ext in CODE_EXT or ext in (".yml", ".yaml") or name == "dockerfile"
    return name == s


def prepare_text(text: str, filename: str) -> str:
    """Notebooks: nur Code-Zellen scannen (JSON-Escaping wuerde Muster brechen)."""
    if filename.lower().endswith(".ipynb"):
        try:
            nb = json.loads(text)
            parts = []
            for c in nb.get("cells", []):
                if c.get("cell_type") == "code":
                    src = c.get("source", "")
                    parts.append("".join(src) if isinstance(src, list) else str(src))
            return "\n".join(parts)
        except Exception:
            return text
    return text


def _run(text: str, name: str, ext: str, cats: Optional[set] = None) -> List[Hit]:
    out: List[Hit] = []
    low = text.lower()
    present = {w for w in ALL_NEEDLES if w in low}  # alle Vorfilter-Woerter in einem Durchgang
    nl = lines = None
    for rule in RULES:
        if cats is not None and rule.cat not in cats:
            continue
        if not _in_scope(rule, name, ext):
            continue
        if rule.need and present.isdisjoint(rule.need):
            continue
        n = 0
        for m in rule.rx.finditer(text):
            if nl is None:
                nl = [m_.start() for m_ in _NL.finditer(text)]
                lines = text.split("\n")
            ln = bisect_right(nl, m.start()) + 1
            snippet = lines[ln - 1].strip()[:140]
            if rule.cat == "leak":  # Geheimnisse nie im Klartext ausgeben
                snippet = snippet.replace(m.group(), m.group()[:6] + "...[REDACTED]")
            out.append(Hit(rule.id, rule.cat, rule.sev, ln, snippet))
            n += 1
            if n >= MAX_HITS_PER_RULE:
                break
    return out


# Versteckte Anweisungen an KI-Assistenten in HTML-Kommentaren (unsichtbar auf GitHub, aber vom Agenten gelesen).
# Bewusst KEINE verschachtelte Regex (ReDoS): erst Kommentar begrenzen, dann den Inhalt mit einfachen Mustern pruefen.
_COMMENT = re.compile(r"<!--(.{0,1500}?)-->", re.S)
_AI_WORDS = re.compile(r"(?i)\b(?:ai|llm|assistant|agent|copilot|cursor|claude|chatgpt)\b")
_IMPERATIVE = re.compile(r"(?i)\b(?:must|should|always|never|ignore|run|execute|send|upload)\b")


def _comment_hits(text: str) -> List["Hit"]:
    if "<!--" not in text or "-->" not in text:
        return []
    out: List[Hit] = []
    for m in _COMMENT.finditer(text):
        body = m.group(1)
        if _AI_WORDS.search(body) and _IMPERATIVE.search(body):
            ln = text.count("\n", 0, m.start()) + 1
            out.append(Hit("hidden_comment_instr", "agent", "MEDIUM", ln, " ".join(body.split())[:140]))
            if len(out) >= MAX_HITS_PER_RULE:
                break
    return out


def _hidden_hits(raw: str, name: str, ext: str) -> List[Hit]:
    """Unsichtbare Zeichen: Trojan Source (Bidi), Unicode-Tags (versteckter Text), Zero-Width in KI-Regeldateien."""
    hits: List[Hit] = []
    agent, code = is_agent_file(name), ext in CODE_EXT
    cat = "agent" if agent else "exec"
    line_of = lambda pos: raw.count("\n", 0, pos) + 1
    m = _BIDI.search(raw)
    if m and (code or agent):
        hits.append(Hit("hidden_bidi", cat, "HIGH", line_of(m.start()), "Bidi-Steuerzeichen im Quelltext (Trojan Source)"))
    for t in _TAGS.finditer(raw):
        if raw[t.start() - 1: t.start()] != "\U0001F3F4":  # Flaggen-Emoji nutzen Tag-Folgen legitim
            hits.append(Hit("hidden_tags", cat, "HIGH", line_of(t.start()), "Unsichtbare Unicode-Tag-Zeichen (versteckter Text)"))
            break
    zw = "".join(_ZWC.findall(raw))
    if agent and len(zw) >= 3:
        hits.append(Hit("hidden_zw", "agent", "HIGH", 1, f"{len(zw)} Zero-Width-Zeichen in KI-Regeldatei"))
    elif code and len(zw) >= 5:
        hits.append(Hit("hidden_zw", "exec", "MEDIUM", 1, f"{len(zw)} Zero-Width-Zeichen im Quelltext"))
    return hits


_B64 = re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{32,}={0,2}(?![A-Za-z0-9+/_-])")
_HEX = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){16,}(?![0-9A-Fa-f])")
_DECODE_CATS = {"exfil", "exec", "stealer", "hook", "agent", "leak", "jailbreak"}


def _try_decode(tok: str, kind: str) -> Optional[str]:
    try:
        if kind == "b64":
            t = tok.replace("-", "+").replace("_", "/")
            b = base64.b64decode(t + "=" * (-len(t) % 4), validate=True)
        else:
            b = bytes.fromhex(tok)
    except Exception:
        return None
    if len(b) >= 2 and b[0] == 0x78 and b[1] in (0x01, 0x5E, 0x9C, 0xDA) or b[:2] == b"\x1f\x8b":
        try:  # eine Kompressionsschicht (zlib/gzip), mit Groessenlimit gegen Bombs
            b = zlib.decompressobj(31 if b[:2] == b"\x1f\x8b" else 15).decompress(b, 2_000_000)
        except Exception:
            return None
    try:
        s = b.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if len(s) < 12 or sum(ch.isprintable() or ch in "\n\r\t" for ch in s) / len(s) < 0.9:
        return None
    return s


def _decoded_hits(text: str, name: str, ext: str) -> List[Hit]:
    """Versteckte Payloads: Base64/Hex(+zlib) dekodieren und mit den kritischen Regeln scannen.
    Gegen den haeufigsten Scammer-Trick (Webhook/URL/Code als Base64-Blob)."""
    hits: List[Hit] = []
    total = used = 0
    seen = set()
    cands = [(m.start(), m.group(), "b64") for m in _B64.finditer(text)] + \
            [(m.start(), m.group(), "hex") for m in _HEX.finditer(text)]
    for pos, tok, kind in cands:
        if used >= MAX_DECODE_CANDIDATES or total >= MAX_DECODED_TOTAL:
            break
        if len(set(tok)) < 8:
            continue
        s = _try_decode(tok, kind)
        used += 1
        if s is None:
            continue
        total += len(s)
        layers = [s]
        for cand in _B64.findall(s)[:3]:  # eine verschachtelte Ebene (Base64 in Base64)
            inner = _try_decode(cand, "b64")
            if inner:
                layers.append(inner)
        ln = text.count("\n", 0, pos) + 1
        for layer in layers:
            for h in _run(layer, "decoded", ".py", _DECODE_CATS):
                key = (h.rule, ln)
                if key in seen:
                    continue
                seen.add(key)
                hits.append(Hit(h.rule, h.cat, h.sev, ln, "[decoded] " + h.snippet[:110]))
    return hits


_ARCHIVE_CTX = re.compile(r"(?i)(?:\.zip|\.rar|\.7z|archive|extract|unzip|download)")
_PWD = re.compile(r"(?i)\bpass(?:word|wd|code)?\s*(?:[:=]|\bis\b)\s*[`\"']?([^\s`\"']{3,32})")


def archive_passwords(readme: str) -> List[bytes]:
    """Passwort aus dem README (Scammer-Standard) - nur wenn in der Naehe von zip/extract/download."""
    out = []
    for m in _PWD.finditer(readme[:200_000]):
        ctx = readme[max(0, m.start() - 160): m.end() + 160]
        if _ARCHIVE_CTX.search(ctx):
            out.append(m.group(1).encode())
    return list(dict.fromkeys(out))[:5]


def _archive_pw_hit(text: str) -> List[Hit]:
    for m in _PWD.finditer(text[:200_000]):
        ctx = text[max(0, m.start() - 160): m.end() + 160]
        if _ARCHIVE_CTX.search(ctx):
            ln = text.count("\n", 0, m.start()) + 1
            return [Hit("claim_archive_password", "claim", "INFO", ln, text.split("\n")[ln - 1].strip()[:140])]
    return []


def scan_text(text: str, filename: str) -> Dict:
    """Volltext-Scan. Liefert Treffer mit Zeilennummer (fuer Viewer) + erkannte Kombinationen."""
    name = PurePosixPath(filename.replace("\\", "/")).name.lower()
    ext = PurePosixPath(name).suffix
    raw = prepare_text(text, filename)[:MAX_SCAN_CHARS]
    hits = _hidden_hits(raw, name, ext)
    clean = _STRIP.sub("", raw)
    hits += _run(clean, name, ext)
    if ext in CODE_EXT or ext in (".html", ".htm"):  # Evasion: 'ex'+'ec' zusammenziehen
        norm = _CONCAT.sub("", clean)
        if norm != clean:
            have = {h.rule for h in hits}
            hits += [h for h in _run(norm, name, ext, _DECODE_CATS) if h.rule not in have]
    hits += _decoded_hits(clean, name, ext)
    if ext in DOC_EXT or ext in (".html", ".htm"):
        hits += _comment_hits(clean)
    if ext in DOC_EXT:
        hits += _archive_pw_hit(clean)
    ids = {h.rule for h in hits}
    combos = [{"label": label, "bonus": bonus}
              for groups, bonus, label in COMBOS if all(g & ids for g in groups)]
    return {"hits": hits, "combos": combos}


def summarize(per_file: Dict[str, Dict]) -> Dict:
    """Repo-Ebene: jede Regel zaehlt EINMAL (kein Hochzaehlen durch viele Dateien)."""
    seen = {}
    combos, leaks, claims, wrapper, ml_by_file, jb_by_file, agent_files = [], [], set(), set(), {}, {}, set()
    for path, res in per_file.items():
        for h in res["hits"]:
            if h.cat in ("exfil", "exec", "stealer", "hook", "inject", "agent"):
                seen.setdefault(h.rule, (h.sev, path, h.line))
                if h.cat == "agent":
                    agent_files.add(path)
            elif h.cat == "leak":
                leaks.append(f"{path}:{h.line} {h.rule}")
            elif h.cat == "claim":
                claims.add(h.rule)
            elif h.cat == "wrapper":
                wrapper.add(h.rule)
            elif h.cat == "ml":
                ml_by_file.setdefault(path, set()).add(h.rule)
            elif h.cat == "jailbreak":
                jb_by_file.setdefault(path, set()).add(h.rule)
        combos += [dict(c, file=path) for c in res["combos"]]
    score = min(sum(SEV_WEIGHT[s] for s, _, _ in seen.values()) + sum(c["bonus"] for c in combos), 100)
    training = [p for p, ids in ml_by_file.items() if len(ids) >= 3]  # ein Treffer ist faelschbar
    return {
        "malware_score": score,
        "level": "HIGH" if score >= 50 else "MEDIUM" if score >= 25 else "LOW",
        "rules_hit": {k: {"sev": v[0], "file": v[1], "line": v[2]} for k, v in seen.items()},
        "combos": combos,
        "leaks": leaks,
        "llm_injection_attempt": any(k.startswith("inj_") for k in seen),
        "jailbreak_files": sorted(p for p, ids in jb_by_file.items()
                                  if len(ids) >= 3 or (len(ids) >= 2 and PurePosixPath(p.lower()).suffix in CODE_EXT)),
        "agent_files": sorted(agent_files),
        "archive_password": "claim_archive_password" in claims,
        "wrapper_signals": sorted(wrapper),
        "real_training_files": training,
        "claims": sorted(claims),
        "claims_vs_reality": {
            "claims_own_model": "claim_own_model" in claims or "claim_evilgpt" in claims,
            "discloses_wrapper": "claim_disclosure" in claims,
            "calls_external_api": bool(wrapper),
            "has_real_training": bool(training),
        },
    }


def viewer_lines(hits: List[Hit]) -> List[str]:
    """Genau dieselben Treffer wie im Audit -> Viewer markiert, was der Scorer sieht."""
    return [f"Line {h.line}: [{h.sev}] {h.rule}: {h.snippet}"
            for h in hits if h.cat not in ("wrapper", "ml", "helper")][:30]


def redact_secrets(text: str) -> str:
    """Geleakte Zugangsdaten nie im Klartext weitergeben (Anzeige/JSON-Bericht): nur die ersten 6 Zeichen bleiben."""
    for rule in RULES:
        if rule.cat == "leak":
            text = rule.rx.sub(lambda m: m.group()[:6] + "...[REDACTED]", text)
    return text
