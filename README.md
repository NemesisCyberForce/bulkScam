# bulkScam modular (AI version) IDEA
##### over py-API , gradio or streamlit
[DE](LIESMICH.md) | [TR](OKUBENI.md)

Use it for free  to check the shit. Have fun & stay secure
> https://huggingface.co/spaces/Alibrown/BulkScam

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


### BinaryAnalyzer
- Analysis of individual files and ZIP archives entirely in memory without write operations during extraction. Direct links and Google Drive links are supported (limit 50 MB).

- Automatic decryption attempt for password-protected ZIP archives using common standard passwords (`infected`, `1234`, `123456`, `password`, `wormgpt`, `fraudgpt`, `github`) as well as supplied passwords.

- Calculation of MD5, SHA1, SHA256, and Shannon entropy.

- Querying the SHA256 hash against the MalwareBazaar API (abuse.ch). A free abuse.ch auth key is required. Without a key the result is "not queried", never "not found".

- Static analysis of Windows PE files (architecture, timestamps, sections, entropy, imports) via `pefile`.

- Extraction of ASCII and UTF-16 strings, public IP addresses, and URLs. The rule set also runs on strings extracted from binaries.

- Detection of packers (UPX, Themida, MPRESS, etc.), bundlers (PyInstaller, PyArmor), and suspicious API calls in six categories: process injection, persistence, credential access, C2 and scam links, download and execute, evasion. Matching is whole word with a minimum number of distinct hits per category.

- RAR and 7z archives are not unpacked. For these only hash, entropy, and password hints from the README are checked.


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
- Optional secondary check of suspicious code files via OpenAI-compatible `/chat/completions` endpoints. Only `.py`, `.pyw`, `.ipynb`, `.js`, `.mjs`, `.sh`, `.ps1`, `.bat`, and `.cmd` files are candidates. Default 6 files, up to 15.

- Preconfigured profiles for HuggingFace Inference Providers, Groq, Google Gemini, OpenRouter, Cerebras, Mistral, OpenAI, and custom OpenAI-compatible endpoints.

- Classification into `REAL_TRAINING`, `API_WRAPPER`, `JAILBREAK_WRAPPER`, `MALWARE_STEALER`, or `UNCLEAR`.

- The LLM result serves exclusively to escalate a finding and cannot downgrade static hits.

- System prompt and user template are editable in the interface. The JSON output format and the injection protection are appended automatically and cannot be edited.

- A test button sends one mini request and checks URL, key, model, and JSON capability.

- Gradio only: optional local model on ZeroGPU (default `Qwen/Qwen2.5-Coder-1.5B-Instruct`), no API key needed.


### User Interfaces
- `src/streamlit_app.py` (Streamlit) and `src/gradio_app.py` (Gradio) offer the same two tabs: GitHub Repository Audit and Binary / Archive Sandbox.

- Sandbox Inspector: read-only viewer for all fetched files and archive members. Files with rule hits are sorted first, binaries are shown as hexdump. Nothing is executed.

- The report can be downloaded as JSON (Streamlit) or opened as JSON (Gradio). Secrets are redacted.

</details>

---

<details>
<summary>Prerequisites and Installation</summary>

### Dependencies
- Python 3.8 or newer (the Docker image uses 3.13)

- `requests` (mandatory)

- `pefile` (optional, for Windows PE header analysis)

- `streamlit` (version 1.37 or newer) for the Streamlit interface

- `gradio` for the Gradio interface. `torch`, `transformers`, and `accelerate` are only needed for the local ZeroGPU model.

- Local module `rules.py` in the same directory as `analyzer_core.py` (defines `CODE_EXT`, `DOC_EXT`, `SEV_WEIGHT`, `scan_text`, `summarize`, `prepare_text`, `viewer_lines`, and more)


### Installation (Streamlit)

```bash
git clone https://github.com/NemesisCyberForce/bulkScam.git
cd bulkScam
pip install -r requirements_streamlit.txt
streamlit run src/streamlit_app.py
```

### Installation (Gradio)

```bash
git clone https://github.com/NemesisCyberForce/bulkScam.git
cd bulkScam
pip install gradio requests pefile
python src/gradio_app.py
```

### Docker (Streamlit on port 8501)
`requirements.txt` only contains comments. Replace it with the Streamlit requirements before building:

```bash
cp requirements_streamlit.txt requirements.txt
docker build -t bulkscam .
docker run -p 8501:8501 bulkscam
```

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
```

- `GITHUB_TOKEN`: no scope needed. Raises the GitHub API limit from 60 to 5000 requests per hour. A token entered in the interface takes priority.

- `ABUSECH_API_KEY`: free key from abuse.ch for the MalwareBazaar lookup.

- `LLM_USE_SERVER_KEYS=1`: `make_llm_config()` falls back to the stored provider API keys if no key was passed. Only set this if you accept that visitors of your instance can use these keys.

- `LLM_ALLOW_PRIVATE_URLS=1`: allows localhost and LAN addresses as LLM base URL (Ollama, llama.cpp, LM Studio, vLLM). Only for self-hosted use. Never set it on a public instance, otherwise visitors can probe your internal network through the URL field.

- `LOCAL_MODEL_ID` and `PRELOAD_LOCAL_MODEL`: Gradio only, local model on ZeroGPU.

### Important Module Constants
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
Archives are processed exclusively in memory. Entries exceeding `MAX_ENTRY` (15 MB), archives with a total sum exceeding `MAX_TOTAL_UNPACKED` (150 MB), and files larger than 1 MB with a compression ratio exceeding a factor of 1000 are discarded. Nested archives are logged but not extracted recursively.

### Prompt Injection Protection
During the LLM audit, the code under review is enclosed within random nonce markers (`<<<UNTRUSTED_CODE_<hex>...>>>`). Lines already flagged by static analysis as `inject` or `jailbreak` are redacted (`[line withheld]`) before transmission to the language model. Files containing recognized injection patterns targeting the scanner itself are completely excluded from LLM transmission. Links in LLM answers are defanged (`hxxp://`).

### Credential Scrubbing and Redaction
The `scrub()` function strips passed tokens and API keys from all caught error messages and HTTP status outputs before they are returned in the result dictionary. Credentials found in scanned files are shown redacted. The Gradio output escapes Markdown characters, because file names and texts come from foreign repositories.

</details>

---

<details>
<summary>Evaluation Classes (Verdicts)</summary>

The `decide()` function returns one of the following results. The LLM can only escalate, never clear.

- `[CRITICAL] POTENTIAL SCAM / MALWARE TRAP DETECTED`: Known malicious package according to OSV, a critical artifact or a MalwareBazaar match, high rating via static rules, strong rule combinations (bonus of 25 or more), or LLM classification as `MALWARE_STEALER` (confidence 70 percent or higher).

- `[FAKE] SCAM FUNNEL: JAILBREAK-PROMPT WRAPPER + UPSELL OF AN UNVERIFIABLE 'PRIVATE MODEL'`: No own training code, use of jailbreak prompts for third-party APIs combined with references to external channels (Telegram, file hosters) for selling alleged private models.

- `[FAKE] LEAD-MAGNET WRAPPER: README UPSELLS AN UNVERIFIABLE PRIVATE MODEL VIA EXTERNAL CHANNEL`: API wrapper without training code whose README promotes a custom model via external channels.

- `[FAKE] SCAM-TYPICAL CLAIMS BUT CODE ONLY CALLS EXTERNAL APIs`: Promotion of unfiltered models in the README with pure invocation of third-party APIs without disclosure.

- `[WARNING] JAILBREAK-PROMPT WRAPPER - NO OWN MODEL, BEHAVIOUR DEPENDS ON A THIRD-PARTY API`: Wrapper around third-party API with embedded jailbreak system prompt.

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

- RAR and 7z contents, AES encrypted ZIP files, and nested archives are not unpacked.

- Without an abuse.ch auth key, MalwareBazaar is not queried.

- The star analysis and the metadata hints are no proof of bought stars.

</details>

---

<details>
<summary>Tests</summary>

```bash
python src/selftest.py
python src/selftest.py --corpus
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
