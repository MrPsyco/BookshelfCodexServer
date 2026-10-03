"""EPUB metadata enrichment pipeline.

Strategy: walk enabled providers in priority order, return as soon as one yields
both a non-empty title AND a non-empty author. The OPF parser runs locally
(zero network), so it's always tried first when active.
"""
from __future__ import annotations

import io
import json
import logging
import os
import re
import time
import zipfile
from typing import Optional
from xml.etree import ElementTree as ET

import requests

log = logging.getLogger("codexserver.epub_washer")


def _norm(s: Optional[str]) -> str:
    if not s:
        return ""
    return re.sub(r"\s+", " ", s).strip()


# ---------------------------------------------------------------------------
# Pipeline runtime settings & external-HTTP helpers.
#
# The enrichment worker (main.py) loads MetadataConfig rows AND app_settings
# fresh from the DB on every batch, then hands them to enrich() via the
# `settings` dict. Settings keys mirror app_settings rows verbatim
# (sanity_check, api_delay_ms, download_missing_covers, language_bias).
# ---------------------------------------------------------------------------

# Mutable module-level state the providers consult for settings that the
# workers need (rate-limit delay, sanity filter, cover download, language bias).
# Set by enrich() on entry so every provider in the chain sees the same values.
_SETTINGS: dict = {
    "sanity_check": True,
    "api_delay_ms": 250,
    "download_missing_covers": False,
    "language_bias": "de-DE",
}

# Where downloaded covers are written (set from main.COVER_CACHE_DIR via
# enrich(..., cover_cache_dir=...)). None disables cover writing.
_COVER_CACHE_DIR: Optional[str] = None

# book.id to stamp into the cover filename (BOOK_ID.jpg).
_BOOK_ID: Optional[int] = None

# Cover URLs resolved by a successful provider call, keyed by provider so a
# later book can't reuse a stale cover from an earlier one.
_COVER_URL: Optional[str] = None

# Providers that make external HTTP calls — used to know when to apply the
# api_delay_ms sleep between requests.
_EXTERNAL_PROVIDERS = {"open_library", "dnb", "google_books"}

# Cleaned (author, title) search hint parsed from the book's filename. Set by
# enrich_from_path_providers (which has the storage path) and consumed by the
# external providers as a fallback query when the OPF yields nothing usable
# and before the raw-text `_first_text_snippet` last resort is tried.
_FILENAME_HINT: tuple[str, str] = ("", "")


def _api_delay_ms() -> int:
    try:
        return int(_SETTINGS.get("api_delay_ms", 250))
    except (TypeError, ValueError):
        return 250


def _delay() -> None:
    ms = _api_delay_ms()
    if ms > 0:
        time.sleep(ms / 1000.0)


def _sanity_enabled() -> bool:
    v = _SETTINGS.get("sanity_check", True)
    if isinstance(v, str):
        return v.strip().lower() in {"1", "true", "yes", "on"}
    return bool(v)


_GARBAGE_PATTERNS = ("scanned by", "corrected by", "unknown", ".epub")


def _is_garbage(title: Optional[str], author: Optional[str]) -> bool:
    """Reject a provider result when title OR author matches a known garbage
    marker (case-insensitive) or is empty/whitespace.

    Returns True when the (title, author) pair should be rejected, signalling
    the caller to fall through to the next provider.
    """
    if _sanity_enabled():
        for field in (title, author):
            s = (field or "").strip().lower()
            if not s:
                return True
            for pat in _GARBAGE_PATTERNS:
                if pat in s:
                    return True
    else:
        # Sanity check disabled: still require both fields non-empty, but skip
        # the pattern scan so legitimate titles containing e.g. "unknown" pass.
        for field in (title, author):
            if not (field or "").strip():
                return True
    return False


def _http_get_json(url: str, *, params: Optional[dict] = None, timeout: int = 8) -> Optional[dict]:
    """Small shared GET returning parsed JSON, or None on any failure."""
    _delay()
    try:
        r = requests.get(url, params=params, timeout=timeout)
        r.raise_for_status()
        return r.json()
    except (requests.RequestException, ValueError) as e:
        log.warning("HTTP GET %s failed: %s", url, e)
        return None


def _http_get_bytes(url: str, timeout: int = 10) -> Optional[bytes]:
    """Small shared GET returning raw bytes (for cover downloads), or None."""
    _delay()
    try:
        r = requests.get(url, timeout=timeout)
        r.raise_for_status()
        return r.content
    except (requests.RequestException, ValueError) as e:
        log.warning("HTTP GET %s failed: %s", url, e)
        return None


# ---- Provider 1: Internal OPF (zipfile-based, no network) ---------------------

def _from_opf(zf: zipfile.ZipFile) -> tuple[str, str]:
    """Find container.xml -> OPF, then dc:title / dc:creator."""
    try:
        container = ET.fromstring(zf.read("META-INF/container.xml"))
    except (KeyError, ET.ParseError) as e:
        log.debug("No container.xml: %s", e)
        return "", ""

    ns = {"c": "urn:oasis:names:tc:opendocument:xmlns:container"}
    rootfile = container.find("c:rootfiles/c:rootfile", ns)
    if rootfile is None:
        return "", ""
    opf_path = rootfile.attrib.get("full-path")
    if not opf_path:
        return "", ""

    try:
        opf_root = ET.fromstring(zf.read(opf_path))
    except (KeyError, ET.ParseError) as e:
        log.debug("Bad OPF %s: %s", opf_path, e)
        return "", ""

    # Use fully-qualified namespaces (xml.etree doesn't apply prefix mappings
    # when traversing across element boundaries, so dc:* lives inside <metadata>).
    PKG = "http://www.idpf.org/2007/opf"
    DC = "http://purl.org/dc/elements/1.1/"
    md = opf_root.find(f"{{{PKG}}}metadata")
    if md is None:
        return "", ""
    title_el = md.find(f"{{{DC}}}title")
    creator_el = md.find(f"{{{DC}}}creator")
    title = _norm(title_el.text if title_el is not None and title_el.text else "")
    author = _norm(creator_el.text if creator_el is not None and creator_el.text else "")
    return title, author


def _provider_internal_opf(blob: bytes, _config) -> tuple[str, str]:
    try:
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            return _from_opf(zf)
    except zipfile.BadZipFile:
        log.warning("Not a valid ZIP/EPUB")
        return "", ""


def enrich_from_path(path: str) -> tuple[str, str]:
    """Extract (title, author) from an EPUB on disk via its own OPF.

    Used by the background metadata-enrichment task, which has storage paths
    (not in-memory blobs). Returns ("", "") if the file is missing, unreadable,
    not a valid EPUB, or its OPF carries no dc:title/dc:creator.

    Reads the file SEQUENTIALLY (one fh.read()) and parses the OPF from an
    in-memory buffer. Doing `zipfile.ZipFile(path)` directly forces random-
    access seeks over the cloud FUSE mount (a cold rclone VFS answers each seek
    with a remote round-trip), which measured ~19s/book vs ~1.1s/book for a
    single sequential read -- a 16x+ difference that was silently throttling
    the whole enrichment backlog.
    """
    try:
        with open(path, "rb") as fh:
            blob = fh.read()
    except (OSError, FileNotFoundError):
        return "", ""
    try:
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            return _from_opf(zf)
    except (zipfile.BadZipFile, ET.ParseError):
        return "", ""


def enrich_from_path_providers(
    path: str,
    configs: list,
    settings: Optional[dict] = None,
    *,
    cover_cache_dir: Optional[str] = None,
    book_id: Optional[int] = None,
) -> tuple[str, str]:
    """Resolve (title, author) using only the providers enabled in the WebUI.

    `configs` is the list of active MetadataConfig rows serialized as plain
    dicts ({provider_name, priority, api_key_or_url}), already filtered for
    is_active=True and sorted by ascending priority. The worker reads these
    fresh on every batch, so enabling/disabling a provider in the UI takes
    effect immediately without a restart.

    Fast path: when `internal_opf` is enabled, read the EPUB's own OPF directly
    (`enrich_from_path` only touches the OPF entries, not the whole file). Only
    when that yields nothing (or OPF is disabled) do we fall back to the
    remaining enabled providers (google_books / ollama / openai / open_library /
    dnb), which need the raw file bytes for text-based lookup.
    """
    global _SETTINGS

    # Apply settings for the OPF fast-path sanity check as well (otherwise the
    # garbage filter would be skipped whenever internal_opf is enabled).
    _SETTINGS = dict(_SETTINGS)
    global _FILENAME_HINT
    _FILENAME_HINT = _filename_search_hint(path)
    if settings:
        for k, v in settings.items():
            _SETTINGS[k] = v

    import types

    def _snap(c: dict) -> types.SimpleNamespace:
        return types.SimpleNamespace(
            provider_name=c.get("provider_name"),
            priority=c.get("priority", 100),
            api_key_or_url=c.get("api_key_or_url"),
        )

    objs = [_snap(c) for c in configs]
    opf_enabled = any(o.provider_name == "internal_opf" for o in objs)
    if opf_enabled:
        t, a = enrich_from_path(path)
        # Run the OPF result through the same garbage filter as every other
        # provider; a garbage OPF title/author falls through to the chain.
        if t and a and not _is_garbage(t, a):
            return t, a

    fallback = [o for o in objs if o.provider_name != "internal_opf"]
    if not fallback:
        return "", ""

    try:
        with open(path, "rb") as fh:
            blob = fh.read()
    except (OSError, FileNotFoundError):
        return "", ""
    if not blob:
        return "", ""
    return enrich(blob, fallback, settings=settings,
                  cover_cache_dir=cover_cache_dir, book_id=book_id)


# ---- Provider 2: Google Books API ---------------------------------------------

def _provider_google_books(blob: bytes, config) -> tuple[str, str]:
    """Use a tiny slice of the EPUB text as a search query (Google has no 'identify this file' API)."""
    try:
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            t, a = _from_opf(zf)
    except zipfile.BadZipFile:
        t, a = "", ""

    # Fill gaps from the cleaned filename hint before falling back to raw text.
    hint_a, hint_t = _FILENAME_HINT
    if not a:
        a = hint_a
    if not t:
        t = hint_t

    query = t or _first_text_snippet(blob)
    if not query:
        return "", ""

    url = "https://www.googleapis.com/books/v1/volumes"
    params = {"q": query, "maxResults": 1}
    # language_bias setting -> Google's langRestrict (e.g. 'de-DE', 'de', 'en').
    lang = (_SETTINGS.get("language_bias") or "").strip()
    if lang:
        params["langRestrict"] = lang
    api_key = (config.api_key_or_url or "").strip()
    if api_key:
        params["key"] = api_key

    data = _http_get_json(url, params=params)
    if not data:
        return "", ""
    items = data.get("items") or []
    if not items:
        return "", ""
    vi = items[0].get("volumeInfo", {})
    title = _norm(vi.get("title"))
    author = _norm((vi.get("authors") or [""])[0])
    # Remember a cover URL for the download-missing-covers step.
    global _COVER_URL
    _COVER_URL = None
    try:
        tl = vi.get("imageLinks") or {}
        if tl.get("thumbnail"):
            _COVER_URL = tl["thumbnail"]
    except Exception:
        pass
    return title, author


def _first_text_snippet(blob: bytes, limit: int = 200) -> str:
    """Last-resort query: pull first text-ish line from any HTML inside the EPUB."""
    try:
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            for name in zf.namelist():
                if name.endswith((".xhtml", ".html", ".htm")):
                    raw = zf.read(name).decode("utf-8", errors="ignore")
                    text = re.sub(r"<[^>]+>", " ", raw)
                    text = _norm(text)
                    if text:
                        return text[:limit]
    except zipfile.BadZipFile:
        pass
    return ""


def _filename_search_hint(path: str) -> tuple[str, str]:
    """Build a cleaned (author, title) search hint out of a filename.

    The filename is NEVER treated as the source of truth — the OPF is — but
    when the OPF is empty, sending "Unknown Author" or raw book prose to the
    external APIs (Open Library / DNB / Google) guarantees zero hits. A cleaned
    hint ("Lastname, Firstname - Series - Title" -> ("Firstname Lastname",
    "Title")) gives those APIs a query they can actually resolve.

    Recognised conventions (from real filenames in this library):
      "Lastname, Firstname - Series NN - Title"  -> ("First Last", "Title")
      "Lastname, Firstname - Title"               -> ("First Last", "Title")
      "Lastname, Firstname (note) Title"          -> ("First Last", "Title")
      "Lastname, Firstname (note) - Title"        -> ("First Last", "Title")

    Returns ("", "") when nothing matches, so the caller falls back to the old
    behaviour instead of trusting a bad parse.
    """
    stem = os.path.splitext(os.path.basename(path))[0].strip()
    if not stem:
        return "", ""

    # Drop parenthetical annotations ("HG", "(Michele, Rebecca)", "(3in1-Bundle)").
    s = re.sub(r"\s*\([^)]*\)", "", stem).strip()
    if not s:
        return "", ""

    author = ""
    title = ""
    if " - " in s:
        left, right = s.split(" - ", 1)
        m = re.match(r"^([^,]+),\s*(.+)$", left.strip())
        if m:
            author = f"{m.group(2).strip()} {m.group(1).strip()}".strip()
        # right may carry "Series NN - Title"; keep the tail after the last " - ".
        title = right.rsplit(" - ", 1)[-1].strip()
    else:
        m = re.match(r"^([^,]+),\s*([^,]+?)\s+(\S.*)$", s)
        if m:
            author = f"{m.group(2).strip()} {m.group(1).strip()}".strip()
            title = m.group(3).strip()

    author = _norm(author)
    title = re.sub(r"^[.\-_–—:;]+", "", (_norm(title) or "")).strip()
    if not author or not title:
        return "", ""
    return author, title


# ---- Provider 3: Ollama (local LLM via /api/generate) -------------------------

def _provider_ollama(blob: bytes, config) -> tuple[str, str]:
    """Ask a local Ollama model to extract {title, author} as JSON.

    Requires the model to support 'format: json'. Falls back to free text parse.
    """
    if not config.api_key_or_url:
        return "", ""

    snippet = _first_text_snippet(blob, limit=1500)
    if not snippet:
        return "", ""

    prompt = (
        "Extract the book title and the primary author from the excerpt below. "
        'Reply strictly with JSON: {"title": "...", "author": "..."}.\n\n'
        f"{snippet}"
    )
    try:
        r = requests.post(
            config.api_key_or_url,
            json={"model": "llama3.1", "prompt": prompt, "stream": False, "format": "json"},
            timeout=30,
        )
        r.raise_for_status()
        out = r.json().get("response", "")
        # crude parse — Ollama may wrap in markdown fences
        m = re.search(r"\{.*?\}", out, re.DOTALL)
        if not m:
            return "", ""
        import json
        parsed = json.loads(m.group(0))
        return _norm(parsed.get("title")), _norm(parsed.get("author"))
    except (requests.RequestException, ValueError, json.JSONDecodeError) as e:
        log.warning("Ollama failed: %s", e)
        return "", ""


# ---- Provider 4: Open Library (search.json) ------------------------------------
#
# Open Library search API: GET
#   https://openlibrary.org/search.json?q=<title>%20<author>&fields=...&limit=1
# Response docs[0] carries title, author_name[0], cover_i. Cover URL is built
# from cover_i via https://covers.openlibrary.org/b/id/COVER_ID-L.jpg

_OPEN_LIBRARY_SEARCH = "https://openlibrary.org/search.json"
_OPEN_LIBRARY_COVER_URL = "https://covers.openlibrary.org/b/id/{cover_id}-L.jpg"


def _provider_open_library(blob: bytes, config) -> tuple[str, str]:
    global _COVER_URL
    _COVER_URL = None

    try:
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            t, a = _from_opf(zf)
    except zipfile.BadZipFile:
        t, a = "", ""

    # Fill gaps from the cleaned filename hint before falling back to raw text.
    hint_a, hint_t = _FILENAME_HINT
    if not a:
        a = hint_a
    if not t:
        t = hint_t

    title_q = t or _first_text_snippet(blob)
    author_q = a or ""
    q = " ".join(x for x in (title_q, author_q) if x).strip()
    if not q:
        return "", ""

    params = {
        "q": q,
        "fields": "title,author_name,cover_i",
        "limit": 1,
    }
    data = _http_get_json(_OPEN_LIBRARY_SEARCH, params=params)
    if not data:
        return "", ""

    docs = data.get("docs") or []
    if not docs:
        return "", ""
    d = docs[0]
    title = _norm(d.get("title"))
    author_names = d.get("author_name") or []
    author = _norm(author_names[0]) if author_names else ""
    try:
        if d.get("cover_i"):
            _COVER_URL = _OPEN_LIBRARY_COVER_URL.format(cover_id=int(d["cover_i"]))
    except (TypeError, ValueError):
        pass
    return title, author


# ---- Provider 5: DNB SRU (Deutsche Nationalbibliothek, MARC21-XML) ------------
#
# SRU searchRetrieve: GET
#   https://services.dnb.de/sru/dnb?version=1.1&operation=searchRetrieve
#       &query=WOE%3D%22<author>%22&recordSchema=MARC21-xml&maximumRecords=1
# Author lives in MARC field 100 subfield $a, title in 245 subfield $a. When the
# author query is empty, fall back to TIT=<title>. No API key required.

_DNB_SRU = "https://services.dnb.de/sru/dnb"

_MARC_NS = {"marc": "http://www.loc.gov/MARC21/slim"}


def _marc_field_value(record, tag: str, subfield: str) -> str:
    """Return the joined text of MARC subfield `subfield` for field `tag`."""
    vals = []
    for datafield in record.findall(f"marc:datafield[@tag='{tag}']", _MARC_NS):
        for sf in datafield.findall(f"marc:subfield[@code='{subfield}']", _MARC_NS):
            if sf.text:
                vals.append(sf.text.strip())
    return _norm(" ".join(vals))


def _provider_dnb(blob: bytes, config) -> tuple[str, str]:
    global _COVER_URL
    _COVER_URL = None

    try:
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            t, a = _from_opf(zf)
    except zipfile.BadZipFile:
        t, a = "", ""

    # Fill gaps from the cleaned filename hint before falling back to raw text.
    hint_a, hint_t = _FILENAME_HINT
    if not a:
        a = hint_a
    if not t:
        t = hint_t

    author = a or ""
    title = t or _first_text_snippet(blob)

    # Build the CQL query: WOE (Werk/Person) for author, TIT fallback for title.
    if author.strip():
        query = f'WOE="{author.strip()}"'
    elif title.strip():
        query = f'TIT="{title.strip()}"'
    else:
        return "", ""

    params = {
        "version": "1.1",
        "operation": "searchRetrieve",
        "query": query,
        "recordSchema": "MARC21-xml",
        "maximumRecords": 1,
    }
    # The raw XML response needs a plain GET (not .json()); use requests directly
    # but still honour the rate-limit delay.
    _delay()
    try:
        r = requests.get(_DNB_SRU, params=params, timeout=8)
        r.raise_for_status()
        raw_xml = r.content
    except (requests.RequestException, ValueError) as e:
        log.warning("DNB SRU failed: %s", e)
        return "", ""

    try:
        root = ET.fromstring(raw_xml)
    except ET.ParseError as e:
        log.warning("DNB SRU returned invalid XML: %s", e)
        return "", ""

    # Find the first <record>/<recordData> in the SRU response.
    record = None
    for rec in root.findall(".//marc:record", _MARC_NS):
        record = rec
        break
    if record is None:
        return "", ""

    out_title = _marc_field_value(record, "245", "a")
    out_author = _marc_field_value(record, "100", "a")
    return out_title, out_author


# ---- Registry & orchestration -------------------------------------------------

PROVIDERS = {
    "internal_opf": _provider_internal_opf,
    "google_books": _provider_google_books,
    "ollama": _provider_ollama,
    "openai": _provider_ollama,  # TODO: real OpenAI implementation, falls back to ollama path
    "open_library": _provider_open_library,
    "dnb": _provider_dnb,
}


def _download_cover(cover_url: str, cover_cache_dir: Optional[str], book_id: Optional[int]) -> None:
    """Fetch a cover image into COVER_CACHE_DIR as BOOK_ID.jpg.

    Only used by the background worker when ``download_missing_covers`` is on
    and the book's EPUB has no embedded cover. Best-effort: any failure is
    logged and swallowed — cover download must never break enrichment.
    """
    if not cover_url:
        return
    if not cover_cache_dir or book_id is None:
        return
    try:
        os.makedirs(cover_cache_dir, exist_ok=True)
    except OSError:
        return
    # Don't clobber an existing cover (extracted or previously downloaded).
    if any(
        os.path.isfile(os.path.join(cover_cache_dir, f"{book_id}{ext}"))
        for ext in (".jpg", ".jpeg", ".png")
    ):
        return
    data = _http_get_bytes(cover_url)
    if not data:
        return
    dest = os.path.join(cover_cache_dir, f"{book_id}.jpg")
    try:
        with open(dest, "wb") as fh:
            fh.write(data)
        log.info("downloaded cover for book %s (%d bytes)", book_id, len(data))
    except OSError as e:
        log.warning("failed to write cover for book %s: %s", book_id, e)


def enrich(
    blob: bytes,
    configs: list,
    settings: Optional[dict] = None,
    *,
    cover_cache_dir: Optional[str] = None,
    book_id: Optional[int] = None,
) -> tuple[str, str]:
    """Walk configs (already filtered for is_active=True, sorted by priority ascending).

    Stops at the first provider that returns both title and author. Applies the
    global `settings` (sanity_check, api_delay_ms, download_missing_covers,
    language_bias) read fresh from the app_settings table by the caller.
    """
    global _SETTINGS, _COVER_CACHE_DIR, _BOOK_ID, _COVER_URL

    # Snapshot settings / runtime context into module globals so every provider
    # in the chain sees the same values for this call.
    _SETTINGS = dict(_SETTINGS)
    if settings:
        for k, v in settings.items():
            _SETTINGS[k] = v
    _COVER_CACHE_DIR = cover_cache_dir
    _BOOK_ID = book_id
    _COVER_URL = None

    download_covers = False
    dc = _SETTINGS.get("download_missing_covers", False)
    if isinstance(dc, str):
        download_covers = dc.strip().lower() in {"1", "true", "yes", "on"}
    else:
        download_covers = bool(dc)

    for cfg in sorted(configs, key=lambda c: c.priority):
        fn = PROVIDERS.get(cfg.provider_name)
        if fn is None:
            log.warning("Unknown provider %s, skipping", cfg.provider_name)
            continue
        try:
            t, a = fn(blob, cfg)
        except Exception as e:  # noqa: BLE001 - any provider failure must not kill the pipeline
            log.exception("Provider %s crashed: %s", cfg.provider_name, e)
            _COVER_URL = None
            continue

        # Sanity/garbage filter: reject results that carry a known garbage
        # marker (or are empty) and fall through to the next provider.
        if _is_garbage(t, a):
            log.info("Provider %s result rejected by sanity check: %r / %r",
                     cfg.provider_name, t, a)
            _COVER_URL = None
            continue

        if t and a:
            log.info("Resolved via %s: %r / %r", cfg.provider_name, t, a)
            if download_covers:
                _download_cover(_COVER_URL, _COVER_CACHE_DIR, _BOOK_ID)
            return t, a

    return "", ""


def safe_storage_path(root: str, author: str, title: str, filename: str) -> str:
    """Build a sanitized 'Author/Title.epub' path inside the storage root."""
    import os
    import unicodedata

    def sanitize(s: str) -> str:
        s = unicodedata.normalize("NFKD", s)
        s = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", s)
        s = re.sub(r"_+", "_", s).strip(" ._")
        return s or "Unknown"

    folder = sanitize(author) if author else "Unknown Author"
    stem = sanitize(title) if title else os.path.splitext(filename)[0]
    return os.path.join(root, folder, f"{stem}.epub")
