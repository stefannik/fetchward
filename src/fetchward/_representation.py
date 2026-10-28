"""Media-type classification, HTML character decoding and safe header metadata.

Acquisition-only inspection: no parsing of JSON, PDFs, images or article content.
"""

from __future__ import annotations

import codecs
import re
from dataclasses import dataclass

from ._types import EncodingRecord, Evidence, EvidenceCategory, Headers, ResourceKind

SNIFF_LIMIT = 4096
META_PRESCAN_LIMIT = 1024

_SAFE_HEADERS = frozenset(
    {
        "content-type",
        "content-encoding",
        "content-length",
        "content-language",
        "content-disposition",
        "etag",
        "last-modified",
        "cache-control",
        "expires",
        "age",
        "vary",
        "date",
        "retry-after",
        "accept-ranges",
    }
)

_HTML_SIGNATURES = (
    b"<!doctype html",
    b"<html",
    b"<head",
    b"<body",
    b"<script",
    b"<iframe",
    b"<h1",
    b"<div",
    b"<font",
    b"<table",
    b"<a",
    b"<style",
    b"<title",
    b"<b",
    b"<br",
    b"<p",
    b"<!--",
)
_BINARY_SIGNATURES = (
    (b"%PDF-", "application/pdf"),
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
    (b"PK\x03\x04", "application/zip"),
    (b"\x1f\x8b\x08", "application/gzip"),
)
_BOMS = (
    (codecs.BOM_UTF8, "utf-8"),
    (codecs.BOM_UTF16_BE, "utf-16-be"),
    (codecs.BOM_UTF16_LE, "utf-16-le"),
)
_META_CHARSET = re.compile(rb"<meta[^>]*?charset\s*=\s*[\"']?\s*([a-zA-Z0-9_:.\-]+)", re.IGNORECASE)


def safe_headers(raw: Headers) -> Headers:
    return Headers((k, v) for k, v in raw.raw_items() if k.lower() in _SAFE_HEADERS)


# Longest decimal Content-Length we attempt to parse. This is far beyond any body the
# acquisition can retain and keeps int() conversion bounded for hostile headers.
MAX_CONTENT_LENGTH_DIGITS = 20


def parse_content_length(value: str | None) -> tuple[int | None, bool]:
    """Return (declared length, malformed) without trusting arbitrary decimal size.

    ``None`` is returned for an absent header. A present but non-decimal, empty or
    unrepresentably long value is reported as malformed so callers can retain the known
    status/body prefix as a structured interruption instead of raising.
    """
    if value is None:
        return None, False
    text = value.strip()
    if not text or len(text) > MAX_CONTENT_LENGTH_DIGITS:
        return None, True
    if not text.isascii() or not text.isdigit():
        return None, True
    try:
        return int(text), False
    except ValueError:
        return None, True


@dataclass(frozen=True)
class MediaType:
    essence: str | None
    charset: str | None


def parse_media_type(value: str | None) -> MediaType:
    if not value:
        return MediaType(None, None)
    essence, _, params = value.partition(";")
    essence = essence.strip().lower()
    if "/" not in essence or " " in essence:
        essence = None
    charset = None
    for param in params.split(";"):
        key, _, val = param.partition("=")
        if key.strip().lower() == "charset":
            charset = val.strip().strip("\"'").lower() or None
    return MediaType(essence or None, charset)


def _kind_for(essence: str) -> ResourceKind:
    if essence in ("text/html", "application/xhtml+xml"):
        return ResourceKind.HTML
    if essence == "application/json" or essence.endswith("+json"):
        return ResourceKind.JSON
    return ResourceKind.FILE


def sniff(body: bytes) -> str | None:
    head = body[:SNIFF_LIMIT]
    for signature, media in _BINARY_SIGNATURES:
        if head.startswith(signature):
            return media
    stripped = head.lstrip(b"\t\n\x0c\r ")
    for bom, _ in _BOMS:
        if stripped.startswith(bom):
            stripped = stripped[len(bom) :].lstrip(b"\t\n\x0c\r ")
    lowered = stripped[:32].lower()
    for signature in _HTML_SIGNATURES:
        if lowered.startswith(signature):
            rest = lowered[len(signature) : len(signature) + 1]
            if signature == b"<!--" or rest in (b" ", b">", b""):
                return "text/html"
    return None


def classify(declared: str | None, body: bytes, attempt_id: str) -> tuple[ResourceKind, str | None, list[Evidence]]:
    """Return kind, inferred media type and disagreement evidence. Declared types win."""
    media = parse_media_type(declared)
    inferred = sniff(body)
    evidence: list[Evidence] = []
    if media.essence is not None:
        kind = _kind_for(media.essence)
        if inferred is not None and _kind_for(inferred) is not kind:
            evidence.append(
                Evidence(
                    "evidence.media_type_disagreement",
                    EvidenceCategory.OBSERVATION,
                    True,
                    attempt_id,
                    facts=(("declared", media.essence), ("inferred", inferred)),
                )
            )
        return kind, inferred, evidence
    if inferred is not None:
        return _kind_for(inferred), inferred, evidence
    return ResourceKind.UNKNOWN, None, evidence


_X_USER_DEFINED = "x-user-defined"


def _decode_x_user_defined(payload: bytes) -> str:
    """WHATWG x-user-defined: ASCII bytes as is, 0x80-0xFF to U+F780-U+F7FF. Never fails."""
    return "".join(chr(b) if b < 0x80 else chr(0xF700 + b) for b in payload)


# WHATWG Encoding Standard labels (https://encoding.spec.whatwg.org/#names-and-labels),
# mapped to the Python codec implementing that encoding's decoder. Only these labels are
# honoured: a server cannot select an arbitrary Python codec (``base64_codec``, ``rot13``,
# ``utf-7`` ...). WHATWG maps several legacy labels to supersets (iso-8859-1 → windows-1252,
# gb2312 → GBK/gb18030, euc-kr → windows-949, shift_jis → windows-31j, big5 → Big5-HKSCS).
_WHATWG_LABELS: dict[str, tuple[str, ...]] = {
    "utf-8": ("unicode-1-1-utf-8", "unicode11utf8", "unicode20utf8", "utf-8", "utf8", "x-unicode20utf8"),
    "cp866": ("866", "cp866", "csibm866", "ibm866"),
    "iso8859-2": ("csisolatin2", "iso-8859-2", "iso-ir-101", "iso8859-2", "iso88592", "iso_8859-2", "iso_8859-2:1987", "l2", "latin2"),
    "iso8859-3": ("csisolatin3", "iso-8859-3", "iso-ir-109", "iso8859-3", "iso88593", "iso_8859-3", "iso_8859-3:1988", "l3", "latin3"),
    "iso8859-4": ("csisolatin4", "iso-8859-4", "iso-ir-110", "iso8859-4", "iso88594", "iso_8859-4", "iso_8859-4:1988", "l4", "latin4"),
    "iso8859-5": ("csisolatincyrillic", "cyrillic", "iso-8859-5", "iso-ir-144", "iso8859-5", "iso88595", "iso_8859-5", "iso_8859-5:1988"),
    "iso8859-6": ("arabic", "asmo-708", "csiso88596e", "csiso88596i", "csisolatinarabic", "ecma-114", "iso-8859-6", "iso-8859-6-e",
                  "iso-8859-6-i", "iso-ir-127", "iso8859-6", "iso88596", "iso_8859-6", "iso_8859-6:1987"),
    "iso8859-7": ("csisolatingreek", "ecma-118", "elot_928", "greek", "greek8", "iso-8859-7", "iso-ir-126", "iso8859-7", "iso88597",
                  "iso_8859-7", "iso_8859-7:1987", "sun_eu_greek"),
    "iso8859-8": ("csiso88598e", "csisolatinhebrew", "hebrew", "iso-8859-8", "iso-8859-8-e", "iso-ir-138", "iso8859-8", "iso88598",
                  "iso_8859-8", "iso_8859-8:1988", "visual", "csiso88598i", "iso-8859-8-i", "logical"),
    "iso8859-10": ("csisolatin6", "iso-8859-10", "iso-ir-157", "iso8859-10", "iso885910", "l6", "latin6"),
    "iso8859-13": ("iso-8859-13", "iso8859-13", "iso885913"),
    "iso8859-14": ("iso-8859-14", "iso8859-14", "iso885914"),
    "iso8859-15": ("csisolatin9", "iso-8859-15", "iso8859-15", "iso885915", "iso_8859-15", "l9"),
    "iso8859-16": ("iso-8859-16",),
    "koi8-r": ("cskoi8r", "koi", "koi8", "koi8-r", "koi8_r"),
    "koi8-u": ("koi8-ru", "koi8-u"),
    "mac-roman": ("csmacintosh", "mac", "macintosh", "x-mac-roman"),
    "cp874": ("dos-874", "iso-8859-11", "iso8859-11", "iso885911", "tis-620", "windows-874"),
    "cp1250": ("cp1250", "windows-1250", "x-cp1250"),
    "cp1251": ("cp1251", "windows-1251", "x-cp1251"),
    "cp1252": ("ansi_x3.4-1968", "ascii", "cp1252", "cp819", "csisolatin1", "ibm819", "iso-8859-1", "iso-ir-100", "iso8859-1",
               "iso88591", "iso_8859-1", "iso_8859-1:1987", "l1", "latin1", "us-ascii", "windows-1252", "x-cp1252"),
    "cp1253": ("cp1253", "windows-1253", "x-cp1253"),
    "cp1254": ("cp1254", "csisolatin5", "iso-8859-9", "iso-ir-148", "iso8859-9", "iso88599", "iso_8859-9", "iso_8859-9:1989",
               "l5", "latin5", "windows-1254", "x-cp1254"),
    "cp1255": ("cp1255", "windows-1255", "x-cp1255"),
    "cp1256": ("cp1256", "windows-1256", "x-cp1256"),
    "cp1257": ("cp1257", "windows-1257", "x-cp1257"),
    "cp1258": ("cp1258", "windows-1258", "x-cp1258"),
    "mac-cyrillic": ("x-mac-cyrillic", "x-mac-ukrainian"),
    "gb18030": ("chinese", "csgb2312", "csiso58gb231280", "gb2312", "gb_2312", "gb_2312-80", "gbk", "iso-ir-58", "x-gbk", "gb18030"),
    "big5hkscs": ("big5", "big5-hkscs", "cn-big5", "csbig5", "x-x-big5"),
    "euc_jp": ("cseucpkdfmtjapanese", "euc-jp", "x-euc-jp"),
    "iso2022_jp": ("csiso2022jp", "iso-2022-jp"),
    "cp932": ("csshiftjis", "ms932", "ms_kanji", "shift-jis", "shift_jis", "sjis", "windows-31j", "x-sjis"),
    "cp949": ("cseuckr", "csksc56011987", "euc-kr", "iso-ir-149", "korean", "ks_c_5601-1987", "ks_c_5601-1989", "ksc5601",
              "ksc_5601", "windows-949"),
    "utf-16-be": ("unicodefffe", "utf-16be"),
    "utf-16-le": ("csunicode", "iso-10646-ucs-2", "ucs-2", "unicode", "unicodefeff", "utf-16", "utf-16le"),
    _X_USER_DEFINED: ("x-user-defined",),  # no Python codec; decoded by _decode_x_user_defined
}
_LABEL_TO_CODEC = {label: codec for codec, labels in _WHATWG_LABELS.items() for label in labels}
# WHATWG "replacement" labels: decoding them is unsafe, so the declaration is not honoured.
_REPLACEMENT_LABELS = frozenset({"csiso2022kr", "hz-gb-2312", "iso-2022-cn", "iso-2022-cn-ext", "iso-2022-kr", "replacement"})


def _codec(label: str | None) -> str | None:
    """Python codec for a WHATWG encoding label, or ``None`` for an unknown/unsafe label."""
    if not label:
        return None
    return _LABEL_TO_CODEC.get(label.strip("\t\n\x0c\r ").lower())


def decode_html(body: bytes, transport_charset: str | None, content_encoding: tuple[str, ...], decoded: bool) -> tuple[str, EncodingRecord]:
    """BOM → transport charset → bounded meta prescan → UTF-8 with replacement."""
    conflicts: list[str] = []
    bom_name = None
    payload = body
    for bom, name in _BOMS:
        if body.startswith(bom):
            bom_name, payload = name, body[len(bom) :]
            break
    transport = _codec(transport_charset)
    if transport_charset and transport is None:
        conflicts.append("transport_charset_unknown")
        if transport_charset.strip().lower() in _REPLACEMENT_LABELS:
            conflicts.append("replacement_encoding_label")
    meta_label = None
    match = _META_CHARSET.search(body[:META_PRESCAN_LIMIT])
    if match:
        meta_label = match.group(1).decode("ascii", "replace").lower()
    meta = _codec(meta_label)
    if meta_label and meta is None:
        conflicts.append("meta_charset_unknown")
        if meta_label in _REPLACEMENT_LABELS:
            conflicts.append("replacement_encoding_label")
    # HTML prescan: a utf-16 meta declaration in a byte stream means utf-8, and
    # x-user-defined in a meta declaration means windows-1252.
    if meta is not None and meta.startswith("utf-16"):
        meta = "utf-8"
    elif meta == _X_USER_DEFINED:
        meta = "cp1252"
    if bom_name:
        chosen, source = bom_name, "bom"
        if transport and bom_name != transport:
            conflicts.append("bom_vs_transport")
    elif transport:
        chosen, source = transport, "transport"
    elif meta:
        chosen, source = meta, "meta"
    else:
        chosen, source = "utf-8", "fallback"
    if transport and meta and transport != meta:
        conflicts.append("transport_vs_meta")
    if chosen == _X_USER_DEFINED:
        text, replaced = _decode_x_user_defined(payload), False
    else:
        text, replaced, chosen, source = _decode_codec(payload, chosen, source, conflicts)
    record = EncodingRecord(
        content_encoding=content_encoding,
        content_decoded=decoded,
        transport_charset=transport_charset,
        bom=bom_name,
        declared_meta_charset=meta_label,
        effective=chosen,
        source=source,
        replacement_used=replaced,
        conflicts=tuple(conflicts),
    )
    return text, record


def _decode_codec(payload: bytes, chosen: str, source: str, conflicts: list[str]) -> tuple[str, bool, str, str]:
    try:
        return payload.decode(chosen), False, chosen, source
    except UnicodeError:
        try:
            return payload.decode(chosen, errors="replace"), True, chosen, source
        except (UnicodeError, LookupError):  # defensive: never let a declaration raise
            conflicts.append("codec_failed")
            return payload.decode("utf-8", errors="replace"), True, "utf-8", "fallback"
