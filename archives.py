"""Archive layer: detect by magic bytes, read everything IN MEMORY, never write extracted files to disk.

Formats
  always (stdlib):   zip (ZipCrypto password), tar, tar.gz/.bz2/.xz, single .gz/.bz2/.xz
  optional libs:     pyzipper (AES-ZIP), py7zr (7z), rarfile + unrar binary (RAR)
Without an optional lib the file is reported as "not readable" (hash/entropy/README-password hints still work).

Protection: entry count, per-entry size, total unpacked size, compression ratio, nesting depth,
streaming decompression with a hard cap (tar.gz bombs), control characters in names are replaced.
Nothing is extracted to a path, so path traversal in member names cannot write anywhere.
"""
from __future__ import annotations

import bz2
import io
import lzma
import re
import tarfile
import zipfile
import zlib
from typing import Callable, Dict, List, Optional, Tuple

try:  # optional
    import pyzipper  # type: ignore
except Exception:  # pragma: no cover
    pyzipper = None
try:
    import py7zr  # type: ignore
except Exception:  # pragma: no cover
    py7zr = None
try:
    import rarfile  # type: ignore
except Exception:  # pragma: no cover
    rarfile = None

MAX_ENTRY = 15 * 1024 * 1024
MAX_TOTAL_UNPACKED = 150 * 1024 * 1024
MAX_ENTRIES = 500
MAX_DEPTH = 3
MAX_RATIO = 1000
COMMON_PASSWORDS = [b"infected", b"1234", b"123456", b"password", b"wormgpt", b"fraudgpt", b"github"]

ARCHIVE_FORMATS = ("zip", "rar", "7z", "tar", "gz", "bz2", "xz")
_NAME_EXT = {"gz": (".gz", ".tgz"), "bz2": (".bz2", ".tbz2", ".tbz"), "xz": (".xz", ".txz")}

Member = Tuple[str, Optional[int], Optional[int], Callable[[], bytes]]  # name, size, compressed size, reader


def capabilities() -> Dict[str, bool]:
    """Which formats can be opened in this environment."""
    import shutil
    rar_ok = rarfile is not None and any(shutil.which(t) for t in ("unrar", "unar", "bsdtar", "7z", "7zz"))
    return {"zip": True, "zip_aes": pyzipper is not None, "tar": True, "gz": True, "bz2": True, "xz": True,
            "7z": py7zr is not None, "rar": bool(rar_ok)}


def detect_format(data: bytes, name: str = "") -> Optional[str]:
    """Magic bytes first (the extension lies). Executables with an appended ZIP (SFX) count as zip."""
    h = data[:512]
    if h[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        return "zip"
    if h[:6] == b"Rar!\x1a\x07":
        return "rar"
    if h[:6] == b"7z\xbc\xaf\x27\x1c":
        return "7z"
    if h[:2] == b"\x1f\x8b":
        return "gz"
    if h[:3] == b"BZh" and h[3:4] in b"123456789" and len(h) > 3:
        return "bz2"
    if h[:6] == b"\xfd7zXZ\x00":
        return "xz"
    if h[257:262] == b"ustar":
        return "tar"
    if h[:2] == b"MZ" or h[:4] == b"\x7fELF":  # SFX: stdlib finds the end-of-central-directory record
        try:
            if zipfile.is_zipfile(io.BytesIO(data)):
                return "zip"
        except Exception:
            pass
    return None


def _clean(name: str) -> str:
    return re.sub(r"[\x00-\x1f]", "?", name)[:200]


def _pw_str(pw: Optional[bytes]) -> Optional[str]:
    if pw is None:
        return None
    try:
        return pw.decode("utf-8")
    except UnicodeDecodeError:
        return pw.decode("latin-1")


class _Ctx:
    def __init__(self, passwords: Optional[List[bytes]], max_depth: int, max_entries: int = MAX_ENTRIES,
                 max_total: int = MAX_TOTAL_UNPACKED):
        self.max_entries = max_entries
        self.max_total = max_total
        self.files: Dict[str, bytes] = {}
        self.skipped: Dict[str, str] = {}
        self.notes: List[str] = []
        self.pwd: Optional[bytes] = None
        self.total = 0
        self.count = 0
        self.max_depth = max_depth
        self.formats: List[str] = []
        seen, cands = set(), [None]
        for p in list(passwords or []) + COMMON_PASSWORDS:
            if p not in seen:
                seen.add(p)
                cands.append(p)
        self.candidates: List[Optional[bytes]] = cands
        self._limit_noted = False

    def note(self, msg: str) -> None:
        if msg not in self.notes:
            self.notes.append(msg)


# ---------------------------------------------------------------------------- decompression
def _decompress(data: bytes, fmt: str, cap: int) -> Tuple[bytes, bool]:
    """Streaming decompression with a hard output cap. -> (bytes, truncated)"""
    out = bytearray()
    step = 1 << 20
    if fmt == "gz":
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        chunk = data
        while True:
            out += d.decompress(chunk, step)
            if len(out) > cap:
                return bytes(out[:cap]), True
            chunk = d.unconsumed_tail
            if not chunk:
                break
        out += d.flush()
    else:
        d = bz2.BZ2Decompressor() if fmt == "bz2" else lzma.LZMADecompressor()
        piece = d.decompress(data, step)
        while True:
            out += piece
            if len(out) > cap:
                return bytes(out[:cap]), True
            if d.eof or d.needs_input:
                break
            piece = d.decompress(b"", step)
    if len(out) > cap:
        return bytes(out[:cap]), True
    return bytes(out), False


# ---------------------------------------------------------------------------- per-format member lists
def _zip_members(data: bytes, ctx: _Ctx) -> List[Member]:
    bio = io.BytesIO(data)
    zf = pyzipper.AESZipFile(bio) if pyzipper is not None else zipfile.ZipFile(bio)
    infos = [i for i in zf.infolist() if not i.is_dir()]
    enc = [i for i in infos if i.flag_bits & 0x1 and i.file_size <= MAX_ENTRY]
    pwd: Optional[bytes] = None
    if enc:
        probe = min(enc, key=lambda i: i.file_size)
        found = False
        for cand in ctx.candidates:
            try:
                zf.read(probe, pwd=cand)
                pwd, found = cand, True
                break
            except NotImplementedError:
                ctx.note("ZIP is AES encrypted - not readable without the optional 'pyzipper' package.")
                break
            except Exception:
                continue
        if found and pwd:
            ctx.pwd = ctx.pwd or pwd
            ctx.note(f"Archive password found: {_pw_str(pwd)}")
        elif not found:
            ctx.note("Archive is encrypted, password unknown (enter the README password).")
    return [(i.filename, i.file_size, i.compress_size, (lambda i=i, pwd=pwd: zf.read(i, pwd=pwd))) for i in infos]


def _tar_members(data: bytes, ctx: _Ctx) -> List[Member]:
    tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:")
    out: List[Member] = []
    skipped_links = 0
    for m in tf:
        if not m.isfile():
            if m.issym() or m.islnk():
                skipped_links += 1
            continue
        out.append((m.name, m.size, None, (lambda m=m: tf.extractfile(m).read())))  # type: ignore[union-attr]
        if len(out) > MAX_ENTRIES * 4:  # do not walk endless headers
            break
    if skipped_links:
        ctx.note(f"{skipped_links} symlink/hardlink entries in tar ignored.")
    return out


def _sevenzip_members(data: bytes, ctx: _Ctx) -> List[Member]:
    if py7zr is None:
        raise _Unsupported("7z archive: reading needs the optional 'py7zr' package - only hash, entropy and "
                           "README password hints were checked.")
    last: Optional[Exception] = None
    for cand in ctx.candidates:
        try:
            sz = py7zr.SevenZipFile(io.BytesIO(data), mode="r", password=_pw_str(cand))
            infos = [i for i in sz.list() if not getattr(i, "is_directory", False)]
            if getattr(sz, "needs_password", lambda: False)() and cand is None:
                continue
            if cand:
                ctx.pwd = ctx.pwd or cand
                ctx.note(f"Archive password found: {_pw_str(cand)}")

            def rd(name: str, sz=sz) -> bytes:
                sz.reset()
                got = sz.read(targets=[name])
                bio = got.get(name)
                return bio.read() if bio is not None else b""

            return [(i.filename, getattr(i, "uncompressed", None), getattr(i, "compressed", None),
                     (lambda n=i.filename: rd(n))) for i in infos]
        except Exception as e:  # wrong password / encrypted header / corrupt
            last = e
            continue
    raise _Unsupported(f"7z archive is encrypted or unreadable ({type(last).__name__ if last else 'password unknown'}) - "
                       "enter the README password.")


def _rar_members(data: bytes, ctx: _Ctx) -> List[Member]:
    if rarfile is None:
        raise _Unsupported("RAR archive: reading needs the optional 'rarfile' package plus an 'unrar' binary - "
                           "only hash, entropy and README password hints were checked.")
    try:
        rf = rarfile.RarFile(io.BytesIO(data))
    except Exception as e:
        raise _Unsupported(f"RAR archive not readable here ({type(e).__name__}: {str(e)[:80]}) - only hash, entropy "
                           "and README password hints were checked.")
    infos = [i for i in rf.infolist() if not i.is_dir()]
    if rf.needs_password() or any(getattr(i, "needs_password", lambda: False)() for i in infos):
        for cand in ctx.candidates:
            if cand is None:
                continue
            try:
                rf.setpassword(_pw_str(cand))
                if infos:
                    rf.read(min(infos, key=lambda i: i.file_size))
                ctx.pwd = ctx.pwd or cand
                ctx.note(f"Archive password found: {_pw_str(cand)}")
                break
            except Exception:
                continue
        else:
            ctx.note("Archive is encrypted, password unknown (enter the README password).")
    return [(i.filename, i.file_size, i.compress_size, (lambda i=i: rf.read(i))) for i in infos]


class _Unsupported(Exception):
    """Format recognised but not readable here; message goes into the notes."""


# ---------------------------------------------------------------------------- recursion
def _store(name: str, b: bytes, ctx: _Ctx, depth: int) -> None:
    fmt = detect_format(b, name)
    if fmt and depth < ctx.max_depth:
        before = len(ctx.files) + len(ctx.skipped)
        try:
            _open(b, name, ctx, depth + 1, prefix=name + "!/")
        except _Unsupported as e:
            ctx.note(f"{name}: {e}")
        except Exception as e:
            ctx.note(f"{name}: nested {fmt} not readable ({type(e).__name__}).")
        if len(ctx.files) + len(ctx.skipped) > before:
            return  # children are stored; the container itself adds nothing to scan
    elif fmt:
        ctx.note(f"Nested archive deeper than {ctx.max_depth} levels not extracted: {name}")
    ctx.files[name] = b


def _process(members: List[Member], ctx: _Ctx, prefix: str, depth: int) -> None:
    for raw_name, size, csize, rd in members:
        if ctx.count >= ctx.max_entries:
            if not ctx._limit_noted:
                ctx.note(f"More than {ctx.max_entries} entries - only the first {ctx.max_entries} are read.")
                ctx._limit_noted = True
            break
        ctx.count += 1
        name = _clean(prefix + raw_name)
        if size is not None and size > MAX_ENTRY:
            ctx.skipped[name] = f"skipped: {size // 1048576} MB > {MAX_ENTRY // 1048576} MB"
        elif ctx.total + (size or 0) > ctx.max_total:
            ctx.skipped[name] = "skipped: total limit (zip bomb protection)"
        elif size and size > 1_048_576 and csize and size / csize > MAX_RATIO:
            ctx.skipped[name] = f"skipped: compression ratio >{MAX_RATIO}x (suspected zip bomb)"
        else:
            try:
                b = rd()
            except Exception as e:
                ctx.skipped[name] = f"not readable (encrypted/corrupt): {str(e)[:80]}"
                continue
            if len(b) > MAX_ENTRY:
                ctx.skipped[name] = f"skipped: {len(b) // 1048576} MB > {MAX_ENTRY // 1048576} MB"
                continue
            ctx.total += len(b)
            _store(name, b, ctx, depth)


def _open(data: bytes, name: str, ctx: _Ctx, depth: int, prefix: str = "") -> None:
    fmt = detect_format(data, name)
    if fmt is None:
        ctx.files[_clean(prefix or name)] = data
        return
    ctx.formats.append(fmt)
    if fmt == "zip":
        if data[:2] in (b"MZ",) or data[:4] == b"\x7fELF":
            ctx.note("Self-extracting archive: executable with an appended ZIP.")
        _process(_zip_members(data, ctx), ctx, prefix, depth)
    elif fmt == "tar":
        _process(_tar_members(data, ctx), ctx, prefix, depth)
    elif fmt in ("gz", "bz2", "xz"):
        room = max(0, ctx.max_total - ctx.total)
        raw, cut = _decompress(data, fmt, room)
        if cut:
            ctx.skipped[_clean(prefix + name)] = "skipped: decompressed size exceeds the limit (bomb protection)"
            return
        if len(raw) > 1_048_576 and len(data) and len(raw) / len(data) > MAX_RATIO:
            ctx.skipped[_clean(prefix + name)] = f"skipped: compression ratio >{MAX_RATIO}x (suspected bomb)"
            return
        if detect_format(raw, "") == "tar":
            _process(_tar_members(raw, ctx), ctx, prefix, depth)
        else:
            base = name.rsplit("/", 1)[-1]
            for ext in _NAME_EXT[fmt]:
                if base.lower().endswith(ext):
                    base = base[: -len(ext)] or "decompressed"
                    break
            else:
                base = base or "decompressed"
            ctx.total += len(raw)
            ctx.count += 1
            _store(_clean(prefix + base), raw, ctx, depth)
    elif fmt == "7z":
        _process(_sevenzip_members(data, ctx), ctx, prefix, depth)
    elif fmt == "rar":
        _process(_rar_members(data, ctx), ctx, prefix, depth)


def read_archive(data: bytes, name: str = "", extra_passwords: Optional[List[bytes]] = None,
                 max_depth: int = MAX_DEPTH, max_entries: int = MAX_ENTRIES, max_total: int = MAX_TOTAL_UNPACKED):
    """-> (files | None, skipped, password, notes, format)
    files is None when the format is not an archive or cannot be read here (caller analyses the raw bytes)."""
    fmt = detect_format(data, name)
    if fmt is None:
        return None, {}, None, [], None
    ctx = _Ctx(extra_passwords, max_depth, max_entries, max_total)
    try:
        _open(data, name or "archive", ctx, 0)
    except _Unsupported as e:
        return None, {}, ctx.pwd, ctx.notes + [str(e)], fmt
    except Exception as e:
        return None, {}, ctx.pwd, ctx.notes + [f"{fmt.upper()} archive not readable: {type(e).__name__}: {str(e)[:80]}"], fmt
    return ctx.files, ctx.skipped, ctx.pwd, ctx.notes, fmt
