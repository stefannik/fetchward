"""Bounded HTTP content-encoding decoding for retained source bytes.

The browser receives the original encoded body and headers; this helper produces the
separate retained source representation. Decoding is bounded by an explicit output budget so a
compressed response cannot expand into an unbounded allocation. Gzip and deflate are decoded
with the standard library; other codings are reported as unsupported rather than being marked
decoded. Corrupt or over-limit streams are reported with stable codes.
"""

from __future__ import annotations

import gzip
import io
import zlib

_SUPPORTED = frozenset({"gzip", "x-gzip", "deflate", "identity"})
_ERROR_UNSUPPORTED = "content_encoding_unsupported"
_ERROR_CORRUPT = "content_encoding_corrupt"
_ERROR_TOO_LARGE = "content_encoding_too_large"


class ContentDecodeError(Exception):
    code: str

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _bounded_gzip(body: bytes, limit: int) -> bytes:
    output: list[bytes] = []
    remaining = limit
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(body), mode="rb") as stream:
            while True:
                chunk = stream.read(min(64 * 1024, remaining + 1))
                if not chunk:
                    break
                if len(chunk) > remaining:
                    raise ContentDecodeError(_ERROR_TOO_LARGE)
                output.append(chunk)
                remaining -= len(chunk)
    except ContentDecodeError:
        raise
    except (OSError, EOFError, zlib.error) as exc:
        raise ContentDecodeError(_ERROR_CORRUPT) from exc
    return b"".join(output)


def _bounded_deflate(body: bytes, limit: int) -> bytes:
    last_error: Exception | None = None
    for window_bits in (zlib.MAX_WBITS, -zlib.MAX_WBITS):
        decompressor = zlib.decompressobj(window_bits)
        output: list[bytes] = []
        remaining = limit
        try:
            for start in range(0, len(body), 64 * 1024):
                chunk = decompressor.decompress(body[start : start + 64 * 1024], remaining + 1)
                if len(chunk) > remaining:
                    raise ContentDecodeError(_ERROR_TOO_LARGE)
                output.append(chunk)
                remaining -= len(chunk)
            tail = decompressor.flush()
            if len(tail) > remaining:
                raise ContentDecodeError(_ERROR_TOO_LARGE)
            output.append(tail)
            if decompressor.eof:
                return b"".join(output)
            last_error = ValueError("truncated deflate stream")
        except ContentDecodeError:
            raise
        except zlib.error as exc:
            last_error = exc
    raise ContentDecodeError(_ERROR_CORRUPT) from last_error


def decode_content(
    body: bytes, encodings: tuple[str, ...], limit: int
) -> tuple[bytes, bool, str | None]:
    """Decode ``body`` in reverse content-encoding order within ``limit`` output bytes.

    Returns ``(body, content_decoded, error_code)``. On an error the original encoded body is
    returned unchanged with ``content_decoded=False`` so callers never label raw bytes as
    decoded.
    """
    current = body
    decoded = False
    for token in reversed(encodings):
        token = token.strip().lower()
        if not token or token == "identity":
            continue
        if token not in _SUPPORTED:
            return body, False, _ERROR_UNSUPPORTED
        decoded = True
        try:
            if token in ("gzip", "x-gzip"):
                current = _bounded_gzip(current, limit)
            else:
                current = _bounded_deflate(current, limit)
        except ContentDecodeError as failure:
            return body, False, failure.code
    return current, decoded, None


__all__ = ["ContentDecodeError", "decode_content"]
