"""EPUB metadata enrichment pipeline.

Strategy: walk enabled providers in priority order, return as soon as one yields
both a non-empty title AND a non-empty author. The OPF parser runs locally
(zero network), so it's always tried first when active.
"""
from __future__ import annotations

import io
import logging
import re
import zipfile
from typing import Optional
from xml.etree import ElementTree as ET

import requests

log = logging.getLogger("codexserver.epub_washer")


def _norm(s: Optional[str]) -> str:
    if not s:
        return ""
    return re.sub(r"\s+", " ", s).strip()


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


# ---- Provider 2: Google Books API ---------------------------------------------

def _provider_google_books(blob: bytes, config) -> tuple[str, str]:
    """Use a tiny slice of the EPUB text as a search query (Google has no 'identify this file' API)."""
    try:
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            t, a = _from_opf(zf)
    except zipfile.BadZipFile:
        t, a = "", ""

    query = t or _first_text_snippet(blob)
    if not query:
        return "", ""

    url = "https://www.googleapis.com/books/v1/volumes"
    params = {"q": query, "maxResults": 1}
    api_key = (config.api_key_or_url or "").strip()
    if api_key:
        params["key"] = api_key

    try:
        r = requests.get(url, params=params, timeout=8)
        r.raise_for_status()
        items = r.json().get("items") or []
        if not items:
            return "", ""
        vi = items[0].get("volumeInfo", {})
        return _norm(vi.get("title")), _norm((vi.get("authors") or [""])[0])
    except (requests.RequestException, ValueError) as e:
        log.warning("Google Books failed: %s", e)
        return "", ""


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


# ---- Registry & orchestration -------------------------------------------------

PROVIDERS = {
    "internal_opf": _provider_internal_opf,
    "google_books": _provider_google_books,
    "ollama": _provider_ollama,
    "openai": _provider_ollama,  # TODO: real OpenAI implementation, falls back to ollama path
}


def enrich(blob: bytes, configs: list) -> tuple[str, str]:
    """Walk configs (already filtered for is_active=True, sorted by priority ascending).

    Stops at the first provider that returns both title and author.
    """
    for cfg in sorted(configs, key=lambda c: c.priority):
        fn = PROVIDERS.get(cfg.provider_name)
        if fn is None:
            log.warning("Unknown provider %s, skipping", cfg.provider_name)
            continue
        try:
            t, a = fn(blob, cfg)
        except Exception as e:  # noqa: BLE001 - any provider failure must not kill the pipeline
            log.exception("Provider %s crashed: %s", cfg.provider_name, e)
            continue
        if t and a:
            log.info("Resolved via %s: %r / %r", cfg.provider_name, t, a)
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
