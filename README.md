---
title: BulkScam - BETA
emoji: 👀
colorFrom: indigo
colorTo: purple
sdk: gradio
sdk_version: 6.32.0
app_file: app.py
license: agpl-3.0
hf_oauth: true
short_description: Repository & Payload Audit Engine
pinned: true
---
# bulkScam modular (AI version)
##### over py-API , gradio or streamlit
[DE](LIESMICH.md) | [TR](OKUBENI.md)

> **Status:** the German/Turkish READMEs may lag behind this English one. Streamlit files are not part of this Space (see the GitHub repo).

Use it for free  to check the shit. Have fun & stay secure
> GPU with own LLM https://huggingface.co/spaces/Alibrown/BulkScam
>
> CPU/Wrapper (same code) https://huggingface.co/spaces/Alibrown/BulkScam-CPU

Static and heuristic analysis tool for detecting compromised machine learning repositories, undeclared API wrappers, scam funnels, and malware in git projects and binary files. Nothing from the analyzed target is ever executed. All user interface texts and report messages are in English, code comments are in German.

---

<details>
<summary>Features and Architecture</summary>

### GitRepoAnalyzer
- Retrieval of repository metadata, file tree, and release assets (latest 10 releases) via the GitHub REST API.

- Prioritized in-memory download and scan of README files, AI agent rule files, package manifests, CI workflows, scripts, source code, documentation, notebooks (`.ipynb`, code cells only), and small data files. Default 40 files, up to 150 files, 30 MB in total.

- Repository description, homepage, and topics are scanned like a text file.

- Metadata hints: repository younger than 30 days, account younger than 90 days, unusual star-to-fork ratio (300 or more stars and fewer than one fork per 100 stars), 3 or fewer commits with 100 or more stars.

- Artifact check: release assets and archives or executables checked into the repository are downloaded (max. 25 MB each, `artifact_max`, default 2) and analyzed like in the Binary tab. Passwords found in the README are tried on password-protected ZIP files.

- Package check: package names from `requirements*.txt`, `package.json`, `pyproject.toml`, `setup.py`, and from install commands in README files, Dockerfiles, `.md`, `.rst`, `.txt`, and `.sh` files (pip, pipx, uv pip, npm, yarn, pnpm, bun).
  - OSV lookup for known malicious packages (ID prefix `MAL-`, max. 60 packages).
  - Registry lookup on PyPI and npm (max. 40 unknown packages): package does not exist (slopsquatting), package younger than 30 days, package younger than 90 days with 2 or fewer releases, name similar to a popular package (typosquat).

- Optional star analysis (GitHub token required, 50 or more stars, about 60 API calls): sample of the most recent stargazers, share of accounts with at most 2 starred repositories, share of stars given within 24 hours. This is a hint, not proof.

- Results from the rule module (`rules.py`), OSV, package check, artifacts, metadata, and the optional LLM analysis are passed to the evaluation function `decide()`.


### ForgeAnalyzer (any git platform, `forge_audit.py`)
- Understands GitHub, GitLab (incl. subgroups), Codeberg / Gitea / Forgejo, Bitbucket, SourceHut, Hugging Face (models, spaces, datasets) and GitHub gists. Self-hosted GitLab/Gitea/Forgejo hosts are detected by probing `/api/v4/version` and `/api/v1/version`.
- Two ways to get the files, one shared analysis (same rules, same `decide()`, same report):
  - **Archive mode**: one ZIP/TGZ download from the platform, read in memory. No API rate limit, no metadata (stars, releases, commit count).
  - **API mode**: the existing GitHub REST path with metadata. **Auto** (default) uses the API for GitHub and falls back to the archive download when the API rate limit is hit.
- Hugging Face and gists are fetched file by file. `.pkl/.pt/.bin/.ckpt` weight files on Hugging Face are listed but **not inspected** (pickle opcode scan is not built yet).
- The platform URL schemes are written from knowledge of the public platforms and are covered by an offline mock test only. If a platform changes its archive URL, only `providers.py` needs a fix.

### Web page audit (`web_scan.py`)
- Static check of an ordinary page: ClickFix (clipboard write + shell command, "Win+R / paste / verify you are human"), hidden text aimed at AI agents, hidden iframes, off-site meta refresh and login forms, executable download links with lure wording, odd link hosts. Script code and page text also run through the normal rule engine.
- Only the delivered HTML is parsed. Nothing is executed and no script/frame/image is loaded. JavaScript-rendered pages are only partly visible; the report says so.

### IOCs and case log (`iocs.py`, `ioc_store.py`)
- Every report lists indicators found **in the content**: domains, public IPs, Telegram handles, Discord webhook ids, Telegram bot ids, crypto wallets (ETH/BTC/XMR/TRX), hashed e-mails, archive passwords and archive hashes. Tokens are never stored (webhook/bot tokens are cut to their public id, e-mails to a short hash). The scammer's real IPs or proxies are **not** visible to a static scan.
- Optional private case log (JSONL), **off unless `IOC_STORE_PATH` is set**. Every case starts as `unreviewed` (quarantine). Cases are linked into clusters by shared strong IOCs (handle, wallet, webhook, bot id, e-mail hash, archive hash) or two shared medium IOCs (IPs/domains); filehost links never link anything. Only `confirmed` cases can be exported, and the export holds IOC type/value only.
- The "Case log" tab appears only when `IOC_STORE_PATH` **and** `CASE_ADMIN_TOKEN` are set. Verdicts are indications, not proof of fraud. The Space disk is ephemeral: copy the file out regularly.

### BinaryAnalyzer
- Analysis of individual files and archives entirely in memory without write operations during extraction. Direct links and Google Drive links are supported (limit 50 MB).

- Automatic decryption attempt for password-protected ZIP archives using common standard passwords (`infected`, `1234`, `123456`, `password`, `wormgpt`, `fraudgpt`, `github`) as well as supplied passwords.

- Calculation of MD5, SHA1, SHA256, and Shannon entropy.

- Querying the SHA256 hash against the MalwareBazaar API (abuse.ch). A free abuse.ch auth key is required. Without a key the result is "not queried", never "not found".

- Static analysis of Windows PE files (architecture, timestamps, sections, entropy, imports) via `pefile`.

- Extraction of ASCII and UTF-16 strings, public IP addresses, and URLs. The rule set also runs on strings extracted from binaries.

- Detection of packers (UPX, Themida, MPRESS, etc.), bundlers (PyInstaller, PyArmor), and suspicious API calls in six categories: process injection, persistence, credential access, C2 and scam links, download and execute, evasion. Matching is whole word with a minimum number of distinct hits per category.

- Archives are detected by magic bytes, not by file extension (an executable with an appended ZIP counts as self-extracting archive). Always available: zip (ZipCrypto password), tar, tar.gz / tar.bz2 / tar.xz, single .gz / .bz2 / .xz. With optional packages: `pyzipper` (AES-ZIP), `py7zr` (7z), `rarfile` + an `unrar`/`unar`/`bsdtar`/`7z` binary (RAR). Without them the file is reported as "not readable" and only hash, entropy and README password hints are checked.
- Nested archives are opened up to depth 3. Limits: entries, size per entry, total unpacked size, compression ratio (>1000x), streaming decompression with a hard cap.


### Rule Engine (rules.py)
- One rule source for scoring and for the viewer. 110 rules in 12 categories (`exfil`, `exec`, `stealer`, `hook`, `agent`, `leak`, `jailbreak`, `inject`, `wrapper`, `ml`, `helper`, `claim`) and 10 combination rules.

- The full text is always scanned. Truncation only applies to the display (30,000 characters).

- Every rule has a literal prefilter, the regular expression only runs if one of its keywords occurs in the text.

- String concatenation tricks (`'ex'+'ec'`) are normalized before scanning.

- Hidden characters: bidirectional control characters (Trojan Source), invisible Unicode tag characters, zero width characters in source code and AI rule files.

- Base64 and hex blobs are decoded (including one zlib or gzip layer) and scanned again.

- AI agent files are checked for hidden instructions: `.cursorrules`, `.windsurfrules`, `.clinerules`, `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `copilot-instructions.md`, `mcp.json`, `.mdc`, and HTML comments that address an AI.

- Leaked credentials (OpenAI, Anthropic, GitHub, Hugging Face, Google, AWS, Stripe, Slack, npm, PyPI, Telegram, Discord) are reported and redacted, only the first 6 characters stay visible.


### OpenAICompatBackend (LLM Audit)
- Optional secondary check of suspicious code files via OpenAI-compatible `/chat/completions` endpoints. Only `.py`, `.pyw`, `.ipynb`, `.js`, `.mjs`, `.sh`, `.ps1`, `.bat`, and `.cmd` files are candidates. Default 6 files, up to 40.

- Preconfigured profiles for HuggingFace Inference Providers, Groq, Google Gemini, OpenRouter, Cerebras, Mistral, OpenAI, and custom OpenAI-compatible endpoints.

- **Rules first, LLM only for the unclear (default "Smart")**: only files with a rule risk of 1-49, or with obfuscation signs (very long lines/tokens, many `\x` escapes) and no rule hit, go to the LLM. Files that are already clear by rules (risk 50 or more) and clean files are not sent. If the rules alone already give CRITICAL, the LLM is not called at all. Mode "All top files" keeps the old behaviour (more tokens). The report shows the numbers in `llm_gate`.
- Classification into `BENIGN` (the default for ordinary code), `REAL_TRAINING`, `API_WRAPPER`, `JAILBREAK_WRAPPER`, `MALWARE_STEALER`, or `UNCLEAR`. The prompt contains no example attack phrases (small models repeat them back), does not hint at scams, and demands verbatim quotes.

- The LLM can only escalate, never clear, **and only with evidence**: a `MALWARE_STEALER` answer counts only if (1) at least one of its quoted indicators appears verbatim in the file and (2) the rules back it up in that file (hits in exfil/exec/stealer/hook) or the file shows obfuscation. It can lead to CRITICAL only if the file's own rule risk is 25 or more; otherwise it is a warning. Unconfirmed answers are shown as "ignored for the verdict".
- A `JAILBREAK_WRAPPER` answer from the LLM never changes a verdict: jailbreak lines are withheld from the LLM, so it cannot see them. Jailbreak detection is rule-only.

- System prompt and user template are editable in the interface. The JSON output format and the injection protection are appended automatically and cannot be edited.

- A test button sends one mini request and checks URL, key, model, and JSON capability.

- Gradio only: optional local model on ZeroGPU (default `Qwen/Qwen2.5-Coder-1.5B-Instruct`), no API key needed.


### User Interfaces
- `app.py` (Gradio, also runs on ZeroGPU) has the tabs Repository Audit, Web Page Audit, Binary / Archive Sandbox and, only with the case-log variables set, Case log (private). A Streamlit UI exists in the GitHub repo only.

- Sandbox Inspector: read-only viewer for all fetched files and archive members. Files with rule hits are sorted first, binaries are shown as hexdump. Nothing is executed.

- The report can be downloaded as JSON (Streamlit) or opened as JSON (Gradio). Secrets are redacted.

</details>

---

<details>
<summary>Prerequisites and Installation</summary>

### Dependencies
- Python 3.10 (the ZeroGPU runtime)

- `requests` (mandatory)

- `pefile` (optional, for Windows PE header analysis)

- `py7zr`, `pyzipper`, `rarfile` (optional, extra archive formats; RAR also needs an `unrar`/`unar`/`bsdtar`/`7z` binary on the system)

- `gradio` for the Gradio interface. `torch`, `transformers`, and `accelerate` are only needed for the local ZeroGPU model.

- All modules must sit in the same directory: `analyzer_core.py`, `rules.py` (**required**, the rule source for the scanner), `archives.py`, `providers.py`, `forge_audit.py`, `web_scan.py`, `iocs.py`, `ioc_store.py`, `app.py`


### Installation (Hugging Face Space, Gradio / ZeroGPU)
Put all `.py` files, `requirements.txt` and `README.md` into the Space root (flat). The README front matter (`sdk: gradio`, `app_file: app.py`) is already set. Optional secrets: see "Configuration".

### Installation (local)

```bash
git clone https://huggingface.co/spaces/Alibrown/BulkScam
cd BulkScam
pip install gradio -r requirements.txt
python app.py
```

Tests (offline, from the repo root): `python dev_tests/run_all.py --fast`

</details>

---

<details>
<summary>Configuration and Environment Variables</summary>

### Environment Variables
```ini
GITHUB_TOKEN=ghp_...
ABUSECH_API_KEY=...
LLM_USE_SERVER_KEYS=1
HF_TOKEN=hf_...
GROQ_API_KEY=gsk_...
GEMINI_API_KEY=...
OPENROUTER_API_KEY=...
CEREBRAS_API_KEY=...
MISTRAL_API_KEY=...
OPENAI_API_KEY=sk-...
LLM_ALLOW_PRIVATE_URLS=1
LOCAL_MODEL_ID=Qwen/Qwen2.5-Coder-1.5B-Instruct
PRELOAD_LOCAL_MODEL=1
IOC_STORE_PATH=/data/cases.jsonl
CASE_ADMIN_TOKEN=choose-a-long-random-token
```

- `GITHUB_TOKEN`: no scope needed. Raises the GitHub API limit from 60 to 5000 requests per hour. A token entered in the interface takes priority.

- `ABUSECH_API_KEY`: free key from abuse.ch for the MalwareBazaar lookup.

- `LLM_USE_SERVER_KEYS=1`: `make_llm_config()` falls back to the stored provider API keys if no key was passed. Only set this if you accept that visitors of your instance can use these keys.

- `LLM_ALLOW_PRIVATE_URLS=1`: allows localhost and LAN addresses as LLM base URL (Ollama, llama.cpp, LM Studio, vLLM). Only for self-hosted use. Never set it on a public instance, otherwise visitors can probe your internal network through the URL field.

- `LOCAL_MODEL_ID` and `PRELOAD_LOCAL_MODEL`: Gradio only, local model on ZeroGPU. Any causal LM that `transformers` can load with `AutoModelForCausalLM` and a chat template works (no `trust_remote_code`). Unknown models must be tested first: use the "Test LLM" button and compare JSON discipline against the default model before trusting it.

- `IOC_STORE_PATH`: enables the private case log (JSONL file). Off when unset. On a Space the disk is ephemeral.

- `CASE_ADMIN_TOKEN`: required to see the "Case log" tab content, change case status or export. Without it the tab is not created.

### Important Module Constants
Archive limits (`MAX_ENTRY`, `MAX_TOTAL_UNPACKED`, `MAX_ENTRIES`, `MAX_DEPTH`, `MAX_RATIO`) live in `archives.py`; repo-archive limits (`REPO_ARCHIVE_MAX` 60 MB, `REPO_UNPACKED_MAX` 250 MB, `REPO_ENTRIES_MAX` 20000) in `forge_audit.py`; the rest in `analyzer_core.py`.

- `TIMEOUT`: 15 seconds for HTTP requests

- `MAX_DOWNLOAD`: 50 MB limit for binary downloads

- `MAX_ENTRY`: 15 MB limit per file in a ZIP archive

- `MAX_TOTAL_UNPACKED`: 150 MB total limit for unpacked data in memory

- `MAX_ENTRIES`: Maximum 500 files per ZIP archive

- `MAX_REPO_FILE`: 3 MB limit per individual repository file

- `MAX_REPO_TOTAL`: 30 MB total limit for all retrieved files of a repository

- `ARTIFACT_MAX_BYTES`: 25 MB limit per release asset or repository archive

- `DISPLAY_CHARS`: 30,000 characters shown per file in the viewer (the scan covers the full text)

- `MAX_PROMPT_CHARS`: 6000 characters per editable prompt

- `MAX_DEPS_CHECK`: 40 unknown packages per registry check


</details>

---

<details>
<summary>Usage (Python API) for analyzer_core.py</summary>

Run these examples from the `src` folder or add it to `PYTHONPATH`. The module is called `analyzer_core`.

### Analyze a GitHub Repository

```python
from analyzer_core import GitRepoAnalyzer, make_llm_config, OpenAICompatBackend

llm_cfg = make_llm_config(
    provider="Groq (free tier)",
    api_key="YOUR_KEY"
)
backend = OpenAICompatBackend(llm_cfg) if llm_cfg else None

analyzer = GitRepoAnalyzer(github_token="YOUR_GITHUB_TOKEN")
result = analyzer.classify_repo(
    url="https://github.com/owner/repo",
    max_files=40,
    backend=backend,
    llm_max_files=6,
    check_osv=True,
    check_deps=True,
    artifact_max=2,
    abuse_key="YOUR_ABUSE_CH_KEY"
)

if "error" in result:
    print(result["error"])
else:
    print(result["verdict"])
    print(result["confidence"])
    print(result["score"])
    print(result["verdict_reasons"])
```

Use `make_llm_config("Off (rules only)")` or `backend=None` to run without an LLM.

### Analyze a Repository on Any Platform

```python
from forge_audit import ForgeAnalyzer

rep = ForgeAnalyzer(github_token=None).classify_url(
    "https://codeberg.org/owner/repo",   # GitHub, GitLab, Gitea/Forgejo, Bitbucket, SourceHut, Hugging Face, gist
    mode="auto",                         # "auto" | "archive" | "api" (api = GitHub only)
    max_files=40,
)
print(rep.get("error") or (rep["verdict"], rep["provider"], rep["mode"]))
print([i for i in rep["iocs"] if i["strength"] == "strong"])
```

### Check a Web Page (static)

```python
import web_scan
rep = web_scan.scan_url("https://example.com/page")
print(rep.get("error") or (rep["verdict"], rep["verdict_reasons"]))
```

### Analyze a Local Binary File or Archive

```python
from pathlib import Path
from analyzer_core import BinaryAnalyzer

report = BinaryAnalyzer.analyze_file(
    file_path=Path("sample.zip"),
    abuse_key="YOUR_ABUSE_CH_KEY",
    extra_passwords=[b"custompass"]
)

print(report["risk_level"])
print(report["score"])
print(report["hashes"])
print(report["heuristics"])
```

### Securely Download and Check an External File

```python
from pathlib import Path
from analyzer_core import BinaryAnalyzer

dest = Path("/tmp/sample.bin")
filename = BinaryAnalyzer.download_file("https://example.com/file.exe", dest)
report = BinaryAnalyzer.analyze_file(dest, display_name=filename)
```

</details>

---

<details>
<summary>Security Mechanisms</summary>

### No Execution
Downloaded files are only read, hashed, decoded, and scanned. Nothing is run, imported, or installed. Archives stay in memory.

### SSRF Protection
Every external URL (file downloads, redirects, custom LLM base URLs) is validated by `check_public_url()` prior to connection establishment. Only `http` and `https` without embedded credentials are permitted. All resolved IPv4 and IPv6 addresses must be globally routable; local networks, loopback, and multicast addresses are blocked. For HTTP redirects, each intermediate destination is checked separately, and the `Authorization` header is removed when switching hosts. A DNS rebinding race between the check and the connection is not fully excluded.

### Zip Bomb Protection
Archives are processed exclusively in memory. Entries exceeding `MAX_ENTRY` (15 MB), archives with a total sum exceeding `MAX_TOTAL_UNPACKED` (150 MB), and files larger than 1 MB with a compression ratio exceeding a factor of 1000 are discarded. gz/bz2/xz streams are decompressed with a hard output cap (so a tar.gz bomb stops early). Nested archives are opened up to depth 3; deeper ones are listed but not opened. Member names never touch the file system (nothing is extracted to a path).

### Prompt Injection Protection
During the LLM audit, the code under review is enclosed within random nonce markers (`<<<UNTRUSTED_CODE_<hex>...>>>`). Lines already flagged by static analysis as `inject` or `jailbreak` are redacted (`[line withheld]`) before transmission to the language model. Files containing recognized injection patterns targeting the scanner itself are completely excluded from LLM transmission. Links in LLM answers are defanged (`hxxp://`).

### Credential Scrubbing and Redaction
The `scrub()` function strips passed tokens and API keys from all caught error messages and HTTP status outputs before they are returned in the result dictionary. Credentials found in scanned files are shown redacted. The Gradio output escapes Markdown characters, because file names and texts come from foreign repositories.

</details>

---

<details>
<summary>Evaluation Classes (Verdicts)</summary>

The `decide()` function returns one of the following results. The LLM can only escalate, never clear, and only with evidence (see above).

- `[CRITICAL] POTENTIAL SCAM / MALWARE TRAP DETECTED`: Known malicious package according to OSV, a critical artifact or a MalwareBazaar match, high rating via static rules, strong rule combinations (bonus of 25 or more), or an evidence-backed LLM classification as `MALWARE_STEALER` (confidence 70 percent or higher, quoted lines confirmed, file rule risk 25 or more).

- `[FAKE] SCAM FUNNEL: JAILBREAK-PROMPT WRAPPER + UPSELL OF AN UNVERIFIABLE 'PRIVATE MODEL'`: No own training code, use of jailbreak prompts for third-party APIs combined with references to external channels (Telegram, file hosters) for selling alleged private models.

- `[FAKE] LEAD-MAGNET WRAPPER: README UPSELLS AN UNVERIFIABLE PRIVATE MODEL VIA EXTERNAL CHANNEL`: API wrapper without training code whose README promotes a custom model via external channels.

- `[FAKE] SCAM-TYPICAL CLAIMS BUT CODE ONLY CALLS EXTERNAL APIs`: Promotion of unfiltered models in the README with pure invocation of third-party APIs without disclosure.

- `[WARNING] JAILBREAK-PROMPT WRAPPER - NO OWN MODEL, BEHAVIOUR DEPENDS ON A THIRD-PARTY API`: Wrapper around third-party API with embedded jailbreak system prompt (found by the static rules, never by the LLM alone).

- `[WARNING] SUSPICIOUS PATTERNS - MANUAL REVIEW`: Medium rule score, executable files in the repository or releases, medium risk artifacts, strongly flagged packages, an archive password in the README together with archives or executables, prompt injection attempts, or clustered metadata anomalies.

- `[WARNING] README CLAIMS OWN MODEL - CODE ONLY CALLS EXTERNAL APIs (verify)`: Claim of a custom model without corresponding training code.

- `[WARNING] CLAIMS WITHOUT ANY CODE EVIDENCE`: Promises in the README without any functional proof in the code.

- `[OK] ML TRAINING CODE FOUND`: Genuine training code identified.

- `[OK] TRAINING CODE + EXTERNAL API CALLS`: Training code as well as calls to external interfaces present.

- `[OK] HONEST API WRAPPER (disclosed)`: Disclosed API wrapper.

- `[INFO] API WRAPPER (no claims found)`: API wrapper without misleading details.

- `[INFO] INSUFFICIENT DATA`: Nothing could be scanned, or the repository has no scannable code (documentation or data only).

- `[INFO] NO ML TRAINING AND NO API USE DETECTED`: Neither training logic nor known AI API calls found.

### Scores
- Malware score of a repository (0 to 100): every rule counts once per repository (`HIGH` 25, `MEDIUM` 10, `INFO` 0) plus the bonus of matched combination rules. Level `HIGH` from 50, `MEDIUM` from 25, otherwise `LOW`. The score only covers malicious code patterns, scam findings are part of the verdict.

- Score of a binary or archive (0 to 100): 30 for a packer or 10 for a bundler, plus 15 per triggered heuristic category, plus the rule score. A MalwareBazaar match sets the score to 100. Risk `CRITICAL` from 70, `MEDIUM` from 40, otherwise `LOW`.

- Confidence is mostly derived from the share of scannable files that were actually scanned (`High` from 80 percent, `Medium` from 40 percent). Weaker findings carry a fixed lower confidence.

</details>

---

<details>
<summary>Limits</summary>

- Static and heuristic analysis delivers hints, not proof. False positives and false negatives are possible. Read the findings and check the code yourself.

- The GitHub API allows 60 requests per hour without a token. Large repositories need a token.

- GitHub may truncate the file tree of very large repositories. The result is then incomplete and the interface says so.

- Files above the size limits are skipped and listed.

- RAR, 7z and AES-ZIP are only read when the optional packages (and for RAR a system binary) are installed; otherwise the file is reported as not readable. Archives nested deeper than 3 levels are not opened. Hugging Face pickle/weight files are not inspected. Archive mode has no stars/commit/release metadata. JavaScript-rendered web pages are only partly visible.

- Without an abuse.ch auth key, MalwareBazaar is not queried.

- The star analysis and the metadata hints are no proof of bought stars.

</details>

---

<details>
<summary>Tests</summary>

```bash
python dev_tests/run_all.py --fast        # about 30 s
python dev_tests/run_all.py               # plus false-positive corpora and fuzz, 6-10 min
python dev_tests/selftest.py --corpus     # selftest only, with package corpus
```

The self test runs offline against a local mock server for GitHub, OSV, PyPI, npm, MalwareBazaar, and an LLM endpoint. It covers the rules, the SSRF protection, verdicts, the package and artifact checks, the LLM path, and the binary analysis. `--corpus` additionally measures false alarms on installed Python packages. The fixtures contain suspicious text patterns on purpose, they are strings, no executable malware.

</details>

---

<details>
<summary>License and Source</summary>

- License: [AGPL v3](LICENSE) or later + [ESOL v2.1](ESOL) or later

- Source: [NCF](https://github.com/NemesisCyberForce/bulkScam/) by @VolkanSah


</details>

---


<details>
<summary>Why this Project</summary>


I was fucked up, scrolling on social networks everywhere and only seeing bullshit and scam, 
while our young wannabe devs are too stupid to understand! So they download a repo or a file on mom's or dad's 
system because they want to develop, and the big shit starts.

Pro tip: You want to learn coding? Sit down for the next 3 or 5 years and read, read, read. After that, 
test locally. Don't touch systems that can get online! Some neighbors I know got big financial problems. 
Why? I blame Hollywood and the wannabe ethical hackers, cybersecurity agents with their #fblifestyle target as an example... 
the hoodie gangs. WTF. IT sucks, really!

AI is nice, and sometimes vibecoding can be really interesting, not the code, but the logic. [Thinking] do you always want 
to read the whole code before testing in a sandbox? Or even you understand the code? No not really!

So I crafted this tool: Push a git or drive link into it, let it scan, read binaries in a sandbox, 
and let the LLM tell you what's happening if you want. WTF, I hate writing docs!


</details>
