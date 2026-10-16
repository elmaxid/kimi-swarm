#!/usr/bin/env python3
"""Sync the [models.*] catalog of config.toml from an OpenAI-compatible gateway.

Adds the model blocks the gateway announces and config.toml is missing, and with
--refresh-metadata it also fills metadata that a block that already exists does
not declare. --refresh-families does the same for the [families] table of
kimi-swarm.toml (the file /kimi-swarm:setup reads).

  default          add missing blocks only
  --refresh-metadata also fill absent fields on existing blocks of the provider
  --refresh-families also sync the families of kimi-swarm.toml
  --provider ID    which [providers.<ID>] to read; required when several have a base_url
  --dry-run        print the plan, its hash and nothing else (the default)
  --apply          write the plan, but only when --expect-plan matches the printed hash
  --expect-plan H  the sha256 of the plan printed by --dry-run (required with --apply)
  --info-url URL   override the derived <base_url without /v1>/model/info

Reading is deliberately dull: GET <base_url>/models for availability, GET
<info-url> to enrich, joined by model_name, bearer auth from the provider block
(api_key, or the variable named by api_key_env). The key is never printed, never
passed on a command line and never copied anywhere. 5 s per request, 15 s in
total, 8 MiB per response, redirects refused; a network or permission error
degrades instead of echoing the gateway response.

Classification uses a blacklist: a mode the gateway spells out as
image_generation, embedding, rerank, audio_speech or audio_transcription is not
a chat model, and a null or absent mode is eligible. A model is only added when
the gateway gives a positive max_input_tokens, because the engine rejects a
[models.*] block without a positive max_context_size at startup.

Existing blocks are only ever widened, never narrowed: capabilities and
support_efforts gain the missing elements and lose none, a scalar is only filled
when it is absent, and a value that contradicts the gateway is reported as
informative and left alone. A model the gateway no longer announces is reported,
never deleted. An `alias@effort` variant is derived from its base by the alias
suffix *and* by sharing provider/model; when the group breaks the invariant
default_effort ∈ support_efforts its changes are omitted and reported, and the
other groups still apply.

Every write goes through a bounded line editor, not a TOML serializer: the BOM,
the line endings, the comments and every untouched byte survive. TOML shapes the
editor cannot rewrite by lines (dotted keys, inline tables) fail closed. Before
anything is written, the original and the candidate are both parsed and compared
structurally, with only the enumerated changes allowed to differ. Writing takes
an exclusive lock, re-checks both file hashes, backs up with mode 0600, writes a
local temporary file, fsyncs it and replaces atomically, keeping the original
mode. The catalog goes first; if the families then fail, they are restored from
their backup and the catalog stays.

Usage:
  sync-models.py [--home DIR] [--provider ID] [--refresh-metadata] [--refresh-families]
  sync-models.py [--home DIR] --apply --expect-plan SHA256 [...]

Exit codes: 0 complete; 1 partial (safe changes may have been applied, see the
summary); 2 arguments; 3 config or validation; 4 catalog unreachable or invalid;
5 lock held or stale plan; 6 write or recovery failure.
"""

import argparse
import copy
import hashlib
import json
import os
import re
import shutil
import socket
import stat
import sys
import tempfile
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

try:
    import fcntl
except ImportError:  # pragma: no cover - POSIX-only locking
    fcntl = None

EXIT_OK = 0
EXIT_PARTIAL = 1
EXIT_USAGE = 2
EXIT_CONFIG = 3
EXIT_CATALOG = 4
EXIT_LOCK = 5
EXIT_WRITE = 6

# An alias (and a provider id) may not start with a dot or a dash, may not carry
# a control character, and may not smuggle a TOML structure character. A model
# id that fails this is refused and reported escaped, never sanitized: a
# model_name with a quote or a newline could inject a [secondary_model] key,
# for example an api_base pointing at another host.
ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,255}$")

# The capability enum the engine actually reads (it compares lower-cased and
# trimmed). video_in and audio_in have no derivable field on this gateway, so
# they are never proposed, only preserved.
CAPABILITY_VALUES = (
    "image_in",
    "video_in",
    "audio_in",
    "thinking",
    "always_thinking",
    "tool_use",
    "dynamically_loaded_tools",
)
CAPABILITY_RANK = {value: index for index, value in enumerate(CAPABILITY_VALUES)}

EFFORT_VALUES = ("none", "minimal", "low", "medium", "high", "xhigh", "max")
EFFORT_RANK = {value: index for index, value in enumerate(EFFORT_VALUES)}

NON_CHAT_MODES = frozenset(
    {"image_generation", "embedding", "rerank", "audio_speech", "audio_transcription"}
)

# The key order of a generated block, and the only keys ever written.
BLOCK_KEYS = (
    "provider",
    "model",
    "display_name",
    "max_context_size",
    "capabilities",
    "support_efforts",
    "default_effort",
)

MAX_RESPONSE_BYTES = 8 * 1024 * 1024
REQUEST_TIMEOUT = 5.0
TOTAL_BUDGET = 15.0
LOCK_NAME = ".kimi-swarm-sync.lock"
FAMILIES_GROUP = "Sin clasificar"

CONTROL_PATTERN = re.compile("[\x00-\x1f\x7f\u0085\u2028\u2029\ud800-\udfff]")
KEY_PATTERN = re.compile(
    r"""^\s*(?:"((?:[^"\\]|\\.)*)"|'([^']*)'|([A-Za-z0-9_-]+))\s*=(?!=)"""
)


class SyncError(Exception):
    """A failure with an exit code, reported without a traceback."""

    def __init__(self, message, code):
        super().__init__(message)
        self.code = code


class NetworkError(Exception):
    """A request that failed, described without the gateway response body."""


def quote_text(value):
    """Return a printable form of untrusted text with controls escaped."""
    if not isinstance(value, str):
        value = repr(value)
    out = []
    for char in value:
        code = ord(char)
        if char == "\\":
            out.append("\\\\")
        elif (
            code < 0x20
            or code == 0x7F
            or 0x80 <= code <= 0x9F
            or code in (0x2028, 0x2029)
            or 0xD800 <= code <= 0xDFFF
        ):
            out.append("\\u%04x" % code)
        else:
            out.append(char)
    return "".join(out)


def resolve_home(explicit):
    if explicit:
        return os.path.realpath(explicit)
    env = os.environ.get("KIMI_CODE_HOME")
    if env:
        return os.path.realpath(env)
    return os.path.realpath(os.path.join(os.path.expanduser("~"), ".kimi-code"))


def validate_id(value):
    """True when value is a safe provider alias or model id."""
    if not isinstance(value, str) or not ID_PATTERN.match(value):
        return False
    segments = value.split("/")
    return not any(segment in (".", "..") or segment == "" for segment in segments)


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def split_origin(base_url):
    """scheme://host:port, with no path, credentials or query."""
    parts = urllib.parse.urlsplit(base_url)
    if not parts.scheme or not parts.netloc:
        return base_url
    return "%s://%s" % (parts.scheme, parts.netloc)


def strip_trailing_v1(base_url):
    return re.sub(r"/v1/?$", "", base_url)


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect())


def http_get_json(url, token, deadline):
    """GET one JSON document, bounded in time, size and redirects."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise NetworkError("time budget exhausted")
    request = urllib.request.Request(url, method="GET")
    request.add_header("Accept", "application/json")
    request.add_header("User-Agent", "kimi-swarm-sync-models")
    if token:
        request.add_header("Authorization", "Bearer " + token)
    try:
        with _OPENER.open(request, timeout=max(0.1, min(REQUEST_TIMEOUT, remaining))) as response:
            if response.status != 200:
                raise NetworkError("HTTP %d" % response.status)
            chunks = []
            total = 0
            while True:
                chunk = response.read(65536)
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > MAX_RESPONSE_BYTES:
                    break
            data = b"".join(chunks)
    except urllib.error.HTTPError as error:
        raise NetworkError("HTTP %d" % error.code) from None
    except (urllib.error.URLError, socket.timeout, OSError, ValueError) as error:
        raise NetworkError(type(error).__name__) from None
    if len(data) > MAX_RESPONSE_BYTES:
        raise NetworkError("response exceeds %d bytes" % MAX_RESPONSE_BYTES)
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise NetworkError("response is not valid JSON") from None


def parse_models_payload(payload):
    """Return the announced model ids, in gateway order."""
    items = payload.get("data") if isinstance(payload, dict) else payload
    if not isinstance(items, list):
        raise NetworkError("unexpected shape for the model list")
    ids = []
    for item in items:
        if isinstance(item, str):
            ids.append(item)
            continue
        if not isinstance(item, dict):
            continue
        for key in ("id", "model_name", "model", "name"):
            value = item.get(key)
            if isinstance(value, str) and value:
                ids.append(value)
                break
    if not ids:
        raise NetworkError("the gateway announced no model")
    return ids


def parse_info_payload(payload):
    """Return {model_name: metadata} from a /model/info document."""
    entries = payload.get("data") if isinstance(payload, dict) else payload
    if isinstance(entries, dict):
        entries = [entries]
    if not isinstance(entries, list):
        raise NetworkError("unexpected shape for the model info")
    info = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        name = None
        for key in ("model_name", "model", "id"):
            value = entry.get(key)
            if isinstance(value, str) and value:
                name = value
                break
        if name is None:
            continue
        nested = entry.get("model_info")
        nested = nested if isinstance(nested, dict) else {}
        merged = dict(entry)
        merged.update(nested)
        merged["__mode__"] = nested.get("mode", entry.get("mode"))
        info[name] = merged
    return info


def canonical_capabilities(values, dropped):
    """Keep the enum values (trimmed, lower-cased) and report the rest."""
    kept = []
    for value in values:
        if not isinstance(value, str):
            dropped.append(repr(value))
            continue
        normalized = value.strip().lower()
        if normalized not in CAPABILITY_RANK:
            dropped.append(value)
        elif normalized not in kept:
            kept.append(normalized)
    return sorted(kept, key=lambda name: CAPABILITY_RANK[name])


def canonical_efforts(values, dropped):
    """Return the canonical effort list, or None when a level is unknown."""
    if values is None:
        return None
    if not isinstance(values, list):
        dropped.append(repr(values))
        return None
    kept = []
    for value in values:
        if not isinstance(value, str):
            dropped.append(repr(value))
            return None
        normalized = value.strip().lower()
        if normalized not in EFFORT_RANK:
            dropped.append(value)
            return None
        if normalized not in kept:
            kept.append(normalized)
    return sorted(kept, key=lambda name: EFFORT_RANK[name])


def canonical_effort(value):
    if not isinstance(value, str):
        return None
    normalized = value.strip().lower()
    return normalized if normalized in EFFORT_RANK else None


def positive_int(value):
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if value > 0 else None


def valid_display_name(value):
    """A display_name the engine will accept: a non-empty string, no controls."""
    if not isinstance(value, str):
        return None
    if not value or value != value.strip() or len(value) > 256:
        return None
    if CONTROL_PATTERN.search(value) or value.startswith("["):
        return None
    return value


class Catalog:
    """What the gateway announced, plus every degradation we hit reading it."""

    def __init__(self):
        self.ids = []
        self.info = {}
        self.metadata_available = True
        self.eligible = {}
        self.excluded = {}

    def classify(self):
        """Fill eligible/excluded. A missing info row means an absent mode, so eligible."""
        for model_id in self.ids:
            record = self.info.get(model_id)
            mode = record.get("__mode__") if record else None
            if isinstance(mode, str) and mode.strip().lower() in NON_CHAT_MODES:
                self.excluded[model_id] = mode.strip().lower()
            else:
                self.eligible[model_id] = record


def read_catalog(base_url, info_url, token, deadline, warnings):
    catalog = Catalog()
    try:
        payload = http_get_json(base_url.rstrip("/") + "/models", token, deadline)
    except NetworkError as error:
        raise SyncError("catalog unreachable (%s): %s" % (split_origin(base_url), error), EXIT_CATALOG)
    try:
        catalog.ids = parse_models_payload(payload)
    except NetworkError as error:
        raise SyncError(
            "catalog is invalid (%s): %s" % (split_origin(base_url), error), EXIT_CATALOG
        )
    try:
        catalog.info = parse_info_payload(http_get_json(info_url, token, deadline))
    except NetworkError as error:
        catalog.metadata_available = False
        catalog.info = {}
        warnings.append("model metadata unavailable (%s): %s" % (split_origin(info_url), error))
    catalog.classify()
    return catalog


# ---------------------------------------------------------------------------
# Line-based TOML editing (bounded, byte preserving)
# ---------------------------------------------------------------------------

def _skip_quoted(line, index):
    """Return the index just past the single-line string starting at index."""
    quote = line[index]
    index += 1
    while index < len(line):
        char = line[index]
        if quote == '"' and char == "\\":
            index += 2
            continue
        if char == quote:
            return index + 1
        index += 1
    return len(line)


def _header_parts(code):
    """Return the dotted segments of a TOML header line, or None."""
    code = code.strip()
    if not code.startswith("["):
        return None
    inner_start = 2 if code.startswith("[[") else 1
    index = inner_start
    close = None
    while index < len(code):
        char = code[index]
        if char in "\"'":
            index = _skip_quoted(code, index)
            continue
        if char == "]":
            close = index
            break
        index += 1
    if close is None or code[close:].strip() not in ("]", "]]"):
        return None
    inner = code[inner_start:close].strip()
    parts = []
    current = ""
    index = 0
    while index < len(inner):
        char = inner[index]
        if char in "\"'":
            end = _skip_quoted(inner, index)
            current += inner[index + 1 : end - 1]
            index = end
            continue
        if char == ".":
            parts.append(current.strip())
            current = ""
            index += 1
            continue
        current += char
        index += 1
    parts.append(current.strip())
    return parts


def _scan_lines(text):
    """Lex each physical line: (continued, code, depth). See uninstall-local.py."""
    records = []
    multiline = None
    depth = 0
    for raw in re.split(r"(?<=\n)", text):
        line = raw.rstrip("\r\n")
        started_in_string = multiline is not None
        start_depth = depth
        cut = len(line)
        index = 0
        while index < len(line):
            if multiline is not None:
                if multiline == '"""' and line[index] == "\\":
                    index += 2
                    continue
                if line.startswith(multiline, index):
                    multiline = None
                    index += 3
                else:
                    index += 1
                continue
            char = line[index]
            if char == "#":
                cut = index
                break
            if line.startswith('"""', index) or line.startswith("'''", index):
                multiline = line[index : index + 3]
                index += 3
                continue
            if char in "\"'":
                index = _skip_quoted(line, index)
                continue
            if char in "[{":
                depth += 1
            elif char in "]}" and depth > 0:
                depth -= 1
            index += 1
        records.append((started_in_string, line[:cut], start_depth))
    return records


def _unquote_key(text):
    out = []
    index = 0
    while index < len(text):
        char = text[index]
        if char == "\\" and index + 1 < len(text):
            nxt = text[index + 1]
            mapping = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\"}
            out.append(mapping.get(nxt, nxt))
            index += 2
            continue
        out.append(char)
        index += 1
    return "".join(out)


def _key_of(code):
    match = KEY_PATTERN.match(code)
    if match is None:
        return None
    if match.group(1) is not None:
        return _unquote_key(match.group(1))
    if match.group(2) is not None:
        return match.group(2)
    return match.group(3)


def _body_end(lines):
    """Index of the end of the real content, excluding a trailing sentinel."""
    return len(lines) - 1 if lines and lines[-1] == "" else len(lines)


def _line_ending(line):
    return line[len(line.rstrip("\r\n")):]


def _trailing_comment(source, code):
    """The comment after `code` on `source`, with the line ending removed.

    The scanner yields the code without its newline, so the raw remainder is the
    comment *plus* the ending; a rewritten line must not grow an extra one.
    """
    tail = source[len(code):]
    ending = _line_ending(tail)
    return tail[: len(tail) - len(ending)].strip()


def _detect_eol(text):
    return "\r\n" if "\r\n" in text else "\n"


def _header_index(records, parts):
    for index, (continued, code, _depth) in enumerate(records):
        if continued or not code.lstrip().startswith("["):
            continue
        if _header_parts(code) == parts:
            return index
    return None


def _table_end(records, start, body_end):
    for index in range(start + 1, body_end):
        continued, code, depth = records[index]
        if continued or depth != 0 or not code.lstrip().startswith("["):
            continue
        if _header_parts(code) is None:
            continue
        return index
    return body_end


def _key_spans(records, start, end):
    """{key: (first_line, last_line)} for the top-level keys of one table."""
    spans = {}
    index = start + 1
    while index < end:
        continued, code, depth = records[index]
        if continued or depth != 0:
            index += 1
            continue
        key = _key_of(code)
        if key is None:
            index += 1
            continue
        last = index
        while last + 1 < end and (records[last + 1][0] or records[last + 1][2] != 0):
            last += 1
        spans[key] = (index, last)
        index = last + 1
    return spans


def _toml_scalar(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return '"%s"' % value.replace("\\", "\\\\").replace('"', '\\"')
    raise SyncError("cannot render %r as TOML" % (value,), EXIT_CONFIG)


def _toml_value(value):
    if isinstance(value, list):
        return "[ %s ]" % ", ".join(_toml_scalar(item) for item in value)
    return _toml_scalar(value)


def _toml_key(name):
    return '"%s"' % name.replace("\\", "\\\\").replace('"', '\\"')


def _render_block(alias, block, eol):
    lines = ["[models.%s]%s" % (_toml_key(alias), eol)]
    for key in BLOCK_KEYS:
        if key in block:
            lines.append("%s = %s%s" % (key, _toml_value(block[key]), eol))
    return lines


def _apply_line_edits(lines, replacements, insertions):
    """Apply both edit lists, which use indices into the original lines.

    Every index is lower than the ones already rewritten, so a descending walk
    never invalidates the remaining edits.
    """
    for start, end, new in sorted(replacements, key=lambda item: -item[0]):
        lines[start : end + 1] = new
    for at, new in sorted(insertions, key=lambda item: -item[0]):
        lines[at:at] = new


def _split_document(text):
    """Return (bom, lines, records, eol) for a text document."""
    bom = ""
    if text.startswith("\ufeff"):
        bom, text = "\ufeff", text[1:]
    lines = re.split(r"(?<=\n)", text)
    return bom, lines, _scan_lines(text), _detect_eol(text)


def parse_document(text, path):
    body = text[1:] if text.startswith("\ufeff") else text
    try:
        return tomllib.loads(body)
    except tomllib.TOMLDecodeError as error:
        raise SyncError("%s does not parse: %s" % (path, error), EXIT_CONFIG)


def _verify_candidate(candidate, expected, path):
    try:
        parsed = tomllib.loads(candidate)
    except tomllib.TOMLDecodeError as error:
        raise SyncError("the rewritten %s would not parse: %s" % (path, error), EXIT_CONFIG)
    if parsed != expected:
        raise SyncError(
            "refusing to write %s: the result would differ from the enumerated plan" % path,
            EXIT_CONFIG,
        )


def edit_models(text, expected, adds, sets, path):
    """Rewrite only the enumerated model blocks and fields.

    adds: [(alias, block)] to insert, sets: [(alias, field, value)] to write into
    a block that already exists. Everything else stays byte for byte. The
    candidate must parse to exactly the expected structure or nothing is used.
    """
    if not adds and not sets:
        return text, False
    bom, lines, records, eol = _split_document(text)
    body_end = _body_end(lines)
    replacements = []
    insertions = []
    blocks = {}

    for alias, _block in adds:
        if _header_index(records, ["models", alias]) is not None:
            raise SyncError(
                "refusing to add [models.%s]: the table already has a header" % quote_text(alias),
                EXIT_CONFIG,
            )

    if adds:
        at = _header_index(records, ["secondary_model"])
        if at is None:
            at = body_end
        new_lines = []
        if at > 0 and lines[at - 1].strip() != "":
            new_lines.append(eol)
        for alias, block in adds:
            new_lines.extend(_render_block(alias, block, eol))
            new_lines.append(eol)
        insertions.append((at, new_lines))

    for alias, field, value in sets:
        if alias not in blocks:
            start = _header_index(records, ["models", alias])
            if start is None:
                raise SyncError(
                    "refusing to edit [models.%s]: it has no header line (dotted keys or an "
                    "inline table), so this tool will not rewrite it by hand" % quote_text(alias),
                    EXIT_CONFIG,
                )
            end = _table_end(records, start, body_end)
            blocks[alias] = (start, end, _key_spans(records, start, end))
        _start, _end, spans = blocks[alias]
        rendered = _toml_value(value)
        if field in spans:
            first, last = spans[field]
            source = lines[first]
            indent = source[: len(source) - len(source.lstrip())]
            comment = _trailing_comment(source, records[first][1])
            if comment:
                comment = " " + comment
            line = "%s%s = %s%s%s" % (indent, field, rendered, comment, _line_ending(source))
            replacements.append((first, last, [line]))
        else:
            if spans:
                anchor = max(last for _field, last in spans.values())
                source = lines[anchor]
                indent = source[: len(source) - len(source.lstrip())]
            else:
                anchor = blocks[alias][0]
                indent = ""
            insertions.append((anchor + 1, ["%s%s = %s%s" % (indent, field, rendered, eol)]))

    _apply_line_edits(lines, replacements, insertions)
    candidate = "".join(lines)
    _verify_candidate(candidate, expected, path)
    return bom + candidate, True


def edit_families(text, expected, group_writes, new_group, path):
    """Rewrite the [families] arrays and, when needed, append the new group."""
    if not group_writes and not new_group:
        return text, False
    bom, lines, records, eol = _split_document(text)
    body_end = _body_end(lines)
    start = _header_index(records, ["families"])
    replacements = []
    insertions = []

    if start is None:
        if "families" in parse_document(text, path):
            raise SyncError(
                "refusing to edit [families] in %s: it has no header line (dotted keys or an "
                "inline table)" % path,
                EXIT_CONFIG,
            )
        at = body_end
        new_lines = []
        if at > 0 and lines[at - 1].strip() != "":
            new_lines.append(eol)
        new_lines.append("[families]%s" % eol)
        new_lines.append("%s = %s%s" % (_toml_key(new_group[0]), _toml_value(new_group[1]), eol))
        insertions.append((at, new_lines))
    else:
        end = _table_end(records, start, body_end)
        spans = _key_spans(records, start, end)
        for group, aliases in group_writes:
            if group not in spans:
                raise SyncError(
                    "refusing to edit families[%s] in %s: it has no line to rewrite"
                    % (quote_text(group), path),
                    EXIT_CONFIG,
                )
            first, last = spans[group]
            source = lines[first]
            indent = source[: len(source) - len(source.lstrip())]
            comment = _trailing_comment(source, records[first][1])
            if comment:
                comment = " " + comment
            line = "%s%s = %s%s%s" % (
                indent,
                _toml_key(group),
                _toml_value(aliases),
                comment,
                _line_ending(source),
            )
            replacements.append((first, last, [line]))
        if new_group:
            if spans:
                anchor = max(last for _field, last in spans.values())
                source = lines[anchor]
                indent = source[: len(source) - len(source.lstrip())]
            else:
                anchor = start
                indent = ""
            insertions.append(
                (
                    anchor + 1,
                    ["%s%s = %s%s" % (indent, _toml_key(new_group[0]), _toml_value(new_group[1]), eol)],
                )
            )

    _apply_line_edits(lines, replacements, insertions)
    candidate = "".join(lines)
    _verify_candidate(candidate, expected, path)
    return bom + candidate, True


# ---------------------------------------------------------------------------
# Plan
# ---------------------------------------------------------------------------

def row(action, alias, field, current, proposed, reason, warning=False, op=None):
    return {
        "action": action,
        "alias": alias,
        "field": field,
        "current": current,
        "proposed": proposed,
        "reason": reason,
        "warning": warning,
        "op": op,
    }


def summarize_block(block):
    parts = []
    if "display_name" in block:
        parts.append("display_name=%s" % quote_text(block["display_name"]))
    parts.append("max_context_size=%s" % block.get("max_context_size"))
    parts.append("capabilities=[%s]" % ", ".join(block.get("capabilities", [])))
    parts.append("support_efforts=[%s]" % ", ".join(block.get("support_efforts", [])))
    if "default_effort" in block:
        parts.append("default_effort=%s" % block["default_effort"])
    return " ".join(parts)


def display(value):
    if value is None:
        return "—"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, list):
        return "[%s]" % ", ".join(quote_text(str(item)) for item in value)
    return quote_text(str(value))


def proposal_for(record):
    """Derive the gateway-side fields; returns (proposal, notes).

    A note is a degradation worth reporting: a capability or an effort level the
    gateway offered outside the enum is dropped and reported, never translated.
    """
    notes = []
    dropped_caps = []
    dropped_efforts = []
    capabilities = []
    if record.get("supports_reasoning") is True:
        capabilities.append("thinking")
    if record.get("supports_vision") is True:
        capabilities.append("image_in")
    if record.get("supports_function_calling") is True:
        capabilities.append("tool_use")
    capabilities = canonical_capabilities(capabilities, dropped_caps)
    if dropped_caps:
        notes.append(("capabilities", dropped_caps, "el gateway ofreció capacidades fuera del enum: se descartan"))
    levels = record.get("reasoning_effort_levels")
    efforts = canonical_efforts(levels, dropped_efforts)
    if dropped_efforts and levels is not None:
        notes.append(
            ("support_efforts", dropped_efforts, "el gateway ofreció niveles de effort desconocidos: se descarta la propuesta")
        )
    default = canonical_effort(record.get("default_reasoning_effort"))
    if default is not None and (efforts is None or default not in efforts):
        default = None
    return {
        "capabilities": capabilities,
        "support_efforts": efforts,
        "default_effort": default,
        "max_context_size": positive_int(record.get("max_input_tokens")),
        "display_name": valid_display_name(record.get("display_name")),
    }, notes


def variant_base(alias, models):
    """The base alias of an `alias@effort` variant, when it really is one.

    Derivation needs the suffix, a valid effort, an existing base block and the
    same provider/model on both, not just the suffix.
    """
    if "@" not in alias:
        return None
    base, _sep, suffix = alias.rpartition("@")
    if canonical_effort(suffix) is None or not base or base not in models:
        return None
    variant = models[alias]
    original = models[base]
    if not isinstance(variant, dict) or not isinstance(original, dict):
        return None
    if variant.get("provider") != original.get("provider"):
        return None
    if variant.get("model") != original.get("model"):
        return None
    return base


def _as_text_list(value):
    return list(value) if isinstance(value, list) else []


def build_plan(config, catalog, provider_id, refresh_metadata, rows):
    """Return (adds, sets) for config.toml, filling rows with what was found."""
    models = config.get("models")
    if models is None:
        models = {}
    if not isinstance(models, dict):
        raise SyncError("[models] is not a table", EXIT_CONFIG)

    adds = []
    sets = []
    announced = set(catalog.ids)

    if not catalog.metadata_available:
        rows.append(
            row(
                "aviso",
                provider_id,
                "(metadata)",
                "—",
                "—",
                "sin /model/info no se puede clasificar ningún modelo: no se proponen altas",
                warning=True,
            )
        )

    for model_id in catalog.ids:
        if not validate_id(model_id):
            rows.append(
                row(
                    "rechazo",
                    quote_text(model_id),
                    "model",
                    "—",
                    "—",
                    "id de modelo inválido: no se incorpora ni se sanea",
                    warning=True,
                )
            )
            continue
        if model_id in catalog.excluded:
            rows.append(
                row(
                    "exclusión",
                    "%s/%s" % (provider_id, model_id),
                    "mode",
                    display(catalog.excluded[model_id]),
                    "—",
                    "el gateway lo declara como modo no-chat",
                )
            )
            continue
        full = "%s/%s" % (provider_id, model_id)
        if full in models:
            continue
        if not catalog.metadata_available:
            continue
        record = catalog.info.get(model_id)
        if record is None:
            rows.append(
                row(
                    "aviso",
                    full,
                    "model_info",
                    "—",
                    "—",
                    "el gateway no trae model_info: no se agrega sin max_context_size",
                    warning=True,
                )
            )
            continue
        proposal, notes = proposal_for(record)
        for field, values, reason in notes:
            rows.append(row("aviso", full, field, "—", display(values), reason, warning=True))
        if proposal["max_context_size"] is None:
            rows.append(
                row(
                    "aviso",
                    full,
                    "max_context_size",
                    "—",
                    "—",
                    "el gateway no anuncia max_input_tokens y el motor exige max_context_size: no se agrega",
                    warning=True,
                )
            )
            continue
        block = {
            "provider": provider_id,
            "model": model_id,
            "max_context_size": proposal["max_context_size"],
            "capabilities": proposal["capabilities"],
            "support_efforts": proposal["support_efforts"] or [],
        }
        if proposal["display_name"] is not None:
            block["display_name"] = proposal["display_name"]
        if proposal["default_effort"] is not None:
            block["default_effort"] = proposal["default_effort"]
        adds.append((full, block))
        rows.append(
            row(
                "alta",
                full,
                "bloque",
                "—",
                summarize_block(block),
                "el gateway lo anuncia y config.toml no lo tiene",
                op={"kind": "add_block", "alias": full, "block": block},
            )
        )

    pending = {}
    for alias in sorted(models):
        block = models[alias]
        if not isinstance(block, dict) or block.get("provider") != provider_id:
            continue
        model_id = block.get("model")
        if not isinstance(model_id, str) or not model_id:
            rows.append(
                row(
                    "aviso",
                    alias,
                    "model",
                    display(model_id),
                    "—",
                    "el bloque no declara un model utilizable: se conserva",
                    warning=True,
                )
            )
            continue
        if model_id not in announced:
            rows.append(
                row(
                    "aviso",
                    alias,
                    "model",
                    model_id,
                    "—",
                    "el gateway no lo anuncia: no anunciado no es muerto, se conserva",
                    warning=True,
                )
            )
            continue
        record = catalog.info.get(model_id)
        if record is None or not catalog.metadata_available:
            continue
        proposal, notes = proposal_for(record)
        if refresh_metadata:
            for field, values, reason in notes:
                rows.append(row("aviso", alias, field, "—", display(values), reason, warning=True))
        local_caps = _as_text_list(block.get("capabilities"))
        local_efforts = block.get("support_efforts")
        local_efforts = _as_text_list(local_efforts) if local_efforts is not None else None

        if refresh_metadata and not isinstance(block.get("capabilities", []), list):
            rows.append(
                row(
                    "aviso",
                    alias,
                    "capabilities",
                    display(block.get("capabilities")),
                    "—",
                    "el bloque no declara capabilities como array: se conserva sin tocar",
                    warning=True,
                )
            )
        elif refresh_metadata and isinstance(block.get("capabilities"), list):
            normalized = {item.strip().lower() for item in local_caps if isinstance(item, str)}
            for value in local_caps:
                if not isinstance(value, str) or value.strip().lower() not in CAPABILITY_RANK:
                    rows.append(
                        row(
                            "aviso",
                            alias,
                            "capabilities",
                            display(value),
                            "—",
                            "valor fuera del enum de capabilities: el motor lo ignora, se conserva",
                            warning=True,
                        )
                    )
            missing = [name for name in proposal["capabilities"] if name not in normalized]
            if missing:
                # Local order first, then the new elements in enum order: a union
                # adds, it never rewrites what was already declared.
                value = local_caps + sorted(missing, key=lambda name: CAPABILITY_RANK[name])
                sets.append((alias, "capabilities", value))
                pending.setdefault(alias, {})["capabilities"] = value
                rows.append(
                    row(
                        "unión",
                        alias,
                        "capabilities",
                        display(local_caps),
                        display(value),
                        "el gateway confirma capacidades que el bloque no declara; nunca se quita ninguna",
                        op={"kind": "set_field", "alias": alias, "field": "capabilities", "value": value},
                    )
                )
            for name in sorted(normalized):
                if name in CAPABILITY_RANK and name not in proposal["capabilities"]:
                    rows.append(
                        row(
                            "contradicción",
                            alias,
                            "capabilities",
                            display(name),
                            "—",
                            "informative: el gateway no lo confirma y el campo no es confiable; no se toca",
                        )
                    )

        if refresh_metadata and block.get("support_efforts") is not None and not isinstance(
            block.get("support_efforts"), list
        ):
            rows.append(
                row(
                    "aviso",
                    alias,
                    "support_efforts",
                    display(block.get("support_efforts")),
                    "—",
                    "el bloque no declara support_efforts como array: se conserva sin tocar",
                    warning=True,
                )
            )
        elif refresh_metadata and proposal["support_efforts"] is not None:
            if local_efforts is None or isinstance(block.get("support_efforts"), list):
                current = list(local_efforts or [])
                normalized = {item.strip().lower() for item in current if isinstance(item, str)}
                missing = [name for name in proposal["support_efforts"] if name not in normalized]
                if missing:
                    value = current + sorted(missing, key=lambda name: EFFORT_RANK[name])
                    sets.append((alias, "support_efforts", value))
                    pending.setdefault(alias, {})["support_efforts"] = value
                    rows.append(
                        row(
                            "unión",
                            alias,
                            "support_efforts",
                            display(current),
                            display(value),
                            "el gateway anuncia niveles que el bloque no declara; nunca se quita ninguno",
                            op={
                                "kind": "set_field",
                                "alias": alias,
                                "field": "support_efforts",
                                "value": value,
                            },
                        )
                    )

        if refresh_metadata and block.get("max_context_size") is None:
            if proposal["max_context_size"] is not None:
                sets.append((alias, "max_context_size", proposal["max_context_size"]))
                pending.setdefault(alias, {})["max_context_size"] = proposal["max_context_size"]
                rows.append(
                    row(
                        "completar",
                        alias,
                        "max_context_size",
                        "—",
                        display(proposal["max_context_size"]),
                        "el campo está ausente y el gateway lo anuncia",
                        op={
                            "kind": "set_field",
                            "alias": alias,
                            "field": "max_context_size",
                            "value": proposal["max_context_size"],
                        },
                    )
                )
        elif (
            refresh_metadata
            and block.get("max_context_size") is not None
            and proposal["max_context_size"] is not None
            and block.get("max_context_size") != proposal["max_context_size"]
        ):
            rows.append(
                row(
                    "contradicción",
                    alias,
                    "max_context_size",
                    display(block.get("max_context_size")),
                    display(proposal["max_context_size"]),
                    "informative: el valor local difiere del gateway; no se toca",
                )
            )

        if refresh_metadata and block.get("default_effort") is None:
            target = proposal["default_effort"]
            effective = pending.get(alias, {}).get("support_efforts", local_efforts or [])
            if target is not None and target in effective:
                sets.append((alias, "default_effort", target))
                pending.setdefault(alias, {})["default_effort"] = target
                rows.append(
                    row(
                        "completar",
                        alias,
                        "default_effort",
                        "—",
                        display(target),
                        "el campo está ausente, el gateway lo anuncia y pertenece a support_efforts",
                        op={"kind": "set_field", "alias": alias, "field": "default_effort", "value": target},
                    )
                )
        elif refresh_metadata and block.get("default_effort") is not None:
            declared = canonical_effort(block.get("default_effort")) or block.get("default_effort")
            effective = pending.get(alias, {}).get("support_efforts", local_efforts or [])
            if declared not in effective:
                rows.append(
                    row(
                        "contradicción",
                        alias,
                        "default_effort",
                        display(block.get("default_effort")),
                        "—",
                        "informative: no pertenece a support_efforts; no se toca",
                    )
                )

    omit_invalid_groups(models, provider_id, sets, pending, rows)
    return adds, sets


def omit_invalid_groups(models, provider_id, sets, pending, rows):
    """Drop every change of an `alias@effort` group that breaks the invariant.

    The invariant has to hold on both members: each default_effort must belong to
    the effective support_efforts of the base and of the variant. Only groups
    with a planned change are examined; a broken group is reported and the rest
    still applies.
    """
    groups = {}
    for alias in models:
        base = variant_base(alias, models)
        if base is None:
            continue
        if not isinstance(models[alias], dict) or models[alias].get("provider") != provider_id:
            continue
        groups.setdefault(base, []).append(alias)

    def effective_efforts(alias):
        if alias in pending and "support_efforts" in pending[alias]:
            return list(pending[alias]["support_efforts"])
        block = models.get(alias)
        value = block.get("support_efforts") if isinstance(block, dict) else None
        return _as_text_list(value) if value is not None else []

    def effective_default(alias):
        if alias in pending and "default_effort" in pending[alias]:
            return pending[alias]["default_effort"]
        block = models.get(alias)
        value = block.get("default_effort") if isinstance(block, dict) else None
        return canonical_effort(value) or value if value is not None else None

    broken = []
    for base, variants in sorted(groups.items()):
        if not any(alias in pending for alias in [base] + variants):
            continue
        base_set = effective_efforts(base)
        for variant in variants:
            variant_set = effective_efforts(variant)
            failure = None
            for member in [base] + variants:
                declared = effective_default(member)
                if declared is None:
                    continue
                if declared not in base_set or declared not in variant_set:
                    failure = (base, variant, member, declared, base_set, variant_set)
                    break
            if failure is not None:
                broken.append(failure)
    if not broken:
        return
    broken_bases = {entry[0] for entry in broken}

    kept = []
    for alias, field, value in sets:
        if (variant_base(alias, models) or alias) in broken_bases:
            continue
        kept.append((alias, field, value))
    sets[:] = kept

    for entry in rows:
        op = entry.get("op")
        if op is None or op.get("kind") != "set_field":
            continue
        if (variant_base(op["alias"], models) or op["alias"]) in broken_bases:
            entry["action"] = "omitido"
            entry["reason"] = "grupo base+variantes inválido: se omiten todos sus cambios"
            entry["warning"] = True
            entry["op"] = None
    for base, variant, member, declared, base_set, variant_set in broken:
        rows.append(
            row(
                "omitido",
                variant,
                "(grupo)",
                display(declared),
                "—",
                "invariante incumplida: el default_effort de %s (%s) no pertenece a support_efforts "
                "del base %s %s ni de la variante %s %s; se omiten los cambios del grupo"
                % (member, declared, base, display(base_set), variant, display(variant_set)),
                warning=True,
            )
        )


def build_families_plan(config, families_config, catalog, provider_id, rows):
    """Return (group_writes, new_group) for kimi-swarm.toml."""
    families = families_config.get("families")
    if families is None:
        families = {}
    if not isinstance(families, dict):
        raise SyncError("families is not a table", EXIT_CONFIG)
    for group, aliases in families.items():
        if not isinstance(aliases, list) or any(not isinstance(item, str) for item in aliases):
            raise SyncError(
                "families[%s] is not an array of aliases" % quote_text(group), EXIT_CONFIG
            )

    announced = set(catalog.ids)

    def announced_alias(alias):
        """True unless this is an alias of our provider the gateway dropped."""
        if "/" not in alias or alias.split("/", 1)[0] != provider_id:
            return True
        model_id = alias.split("/", 1)[1]
        if "@" in model_id:
            base, _sep, suffix = model_id.rpartition("@")
            if base and canonical_effort(suffix) is not None:
                model_id = base
        return model_id in announced

    group_writes = []
    grouped = set()
    for group, aliases in families.items():
        kept = []
        removed = []
        for alias in aliases:
            (kept if announced_alias(alias) else removed).append(alias)
        for alias in removed:
            rows.append(
                row(
                    "retirar",
                    alias,
                    "families[%s]" % quote_text(group),
                    alias,
                    "—",
                    "el gateway ya no lo anuncia: referencia retirada del grupo",
                )
            )
        if removed:
            group_writes.append((group, kept))
        grouped.update(kept)

    ungrouped = sorted(
        "%s/%s" % (provider_id, model_id)
        for model_id in catalog.eligible
        if "%s/%s" % (provider_id, model_id) not in grouped
    )
    new_group = None
    if ungrouped:
        existing = families.get(FAMILIES_GROUP)
        if isinstance(existing, list):
            group_writes = [(g, v) for g, v in group_writes if g != FAMILIES_GROUP]
            group_writes.append((FAMILIES_GROUP, list(existing) + ungrouped))
        else:
            new_group = (FAMILIES_GROUP, ungrouped)
        for alias in ungrouped:
            rows.append(
                row(
                    "agregar",
                    alias,
                    "families[%s]" % FAMILIES_GROUP,
                    "—",
                    alias,
                    "alias base de chat disponible y sin agrupar",
                )
            )

    pool = config.get("secondary_model")
    pool_models = pool.get("models") if isinstance(pool, dict) else None
    if isinstance(pool_models, dict):
        for alias in sorted(pool_models):
            if not isinstance(alias, str) or "/" not in alias:
                continue
            if alias.split("/", 1)[0] != provider_id:
                continue
            if not announced_alias(alias):
                rows.append(
                    row(
                        "aviso",
                        alias,
                        "[secondary_model.models]",
                        alias,
                        "—",
                        "el pool referencia un alias que el gateway no anuncia; el pool no se toca",
                        warning=True,
                    )
                )
    return group_writes, new_group


# ---------------------------------------------------------------------------
# Report and plan hash
# ---------------------------------------------------------------------------

def render_table(rows):
    header = ("acción", "alias", "campo", "actual", "propuesta", "motivo")
    lines = [list(header)]
    for entry in rows:
        lines.append(
            [
                entry["action"],
                entry["alias"],
                entry["field"],
                display(entry["current"]),
                display(entry["proposed"]),
                entry["reason"],
            ]
        )
    widths = [max(len(line[index]) for line in lines) for index in range(len(header))]
    out = []
    for position, line in enumerate(lines):
        out.append(" | ".join(line[index].ljust(widths[index]) for index in range(len(header))).rstrip())
        if position == 0:
            out.append("-+-".join("-" * width for width in widths))
    return "\n".join(out)


def plan_hash(payload):
    text = json.dumps(payload, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    return sha256_bytes(text.encode("utf-8"))


def count_actions(rows):
    counts = {}
    for entry in rows:
        counts[entry["action"]] = counts.get(entry["action"], 0) + 1
    return counts


# ---------------------------------------------------------------------------
# Writing
# ---------------------------------------------------------------------------

class FileLock:
    """Exclusive lock shared by the two writes of one run."""

    def __init__(self, path):
        self.path = path
        self.handle = None

    def acquire(self):
        if fcntl is None:  # pragma: no cover - non-POSIX host
            return True
        self.handle = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(self.handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(self.handle)
            self.handle = None
            return False
        return True

    def release(self):
        if self.handle is None:
            return
        try:
            fcntl.flock(self.handle, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(self.handle)
        self.handle = None


def backup_file(path):
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    backup = "%s.%s.bak" % (path, stamp)
    if os.path.realpath(backup) == os.path.realpath(path):
        raise SyncError("refusing to back up %s onto itself" % path, EXIT_WRITE)
    os.makedirs(os.path.dirname(backup) or ".", exist_ok=True)
    shutil.copy2(path, backup)
    os.chmod(backup, 0o600)
    return backup


def write_atomic(path, text, mode):
    """Local temporary file, fsync, atomic replace, original mode kept."""
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    handle, temporary = tempfile.mkstemp(dir=directory, prefix=".sync-models-", suffix=".tmp")
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
        directory_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def file_mode(path, default=0o600):
    if os.path.isfile(path):
        return stat.S_IMODE(os.stat(path).st_mode)
    return default


def read_bytes(path):
    with open(path, "rb") as handle:
        return handle.read()


def decode_text(data, path):
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise SyncError("%s is not valid UTF-8: %s" % (path, error), EXIT_CONFIG)


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main(argv=None):
    """Entry point: every SyncError becomes its exit code, never a traceback."""
    try:
        return _run(argv)
    except SyncError as error:
        sys.stderr.write("error: %s\n" % error)
        return error.code


def _run(argv=None):
    parser = argparse.ArgumentParser(
        description="Sync the [models.*] catalog of config.toml from an OpenAI-compatible gateway"
    )
    parser.add_argument("--home", help="KIMI_CODE_HOME (default: $KIMI_CODE_HOME or ~/.kimi-code)")
    parser.add_argument(
        "--provider", help="provider id in [providers.*]; required when several have a base_url"
    )
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument(
        "--dry-run",
        dest="apply",
        action="store_false",
        default=False,
        help="print the plan and change nothing (default)",
    )
    modes.add_argument("--apply", dest="apply", action="store_true", help="write the changes")
    parser.add_argument(
        "--expect-plan",
        metavar="SHA256",
        help="the plan hash printed by --dry-run (required with --apply)",
    )
    parser.add_argument(
        "--refresh-metadata", action="store_true", help="also fill absent fields on existing blocks"
    )
    parser.add_argument(
        "--refresh-families", action="store_true", help="also sync the families of kimi-swarm.toml"
    )
    parser.add_argument("--info-url", help="override the derived /model/info URL")
    args = parser.parse_args(argv)

    if args.apply and not args.expect_plan:
        parser.error("--apply requires --expect-plan SHA256 (run --dry-run first)")

    home = resolve_home(args.home)
    config_path = os.path.join(home, "config.toml")
    families_path = os.path.join(home, "kimi-swarm.toml")
    lock_path = os.path.join(home, LOCK_NAME)

    if not os.path.isfile(config_path):
        sys.stderr.write("error: no config.toml at %s\n" % config_path)
        return EXIT_CONFIG
    try:
        original_bytes = read_bytes(config_path)
    except OSError as error:
        sys.stderr.write("error: cannot read %s: %s\n" % (config_path, error))
        return EXIT_CONFIG
    original_text = decode_text(original_bytes, config_path)
    config = parse_document(original_text, config_path)

    providers = config.get("providers")
    if not isinstance(providers, dict):
        sys.stderr.write("error: config.toml has no [providers] table\n")
        return EXIT_CONFIG
    candidates = sorted(
        name
        for name, block in providers.items()
        if isinstance(block, dict)
        and isinstance(block.get("base_url"), str)
        and block["base_url"].strip()
    )
    if args.provider:
        if not validate_id(args.provider):
            sys.stderr.write(
                "error: invalid --provider %s: must match ^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,255}$\n"
                % quote_text(args.provider)
            )
            return EXIT_USAGE
        if args.provider not in providers:
            sys.stderr.write(
                "error: no [providers.%s] in %s\n" % (quote_text(args.provider), config_path)
            )
            return EXIT_CONFIG
        provider_id = args.provider
        base_url = providers[provider_id].get("base_url")
        if not isinstance(base_url, str) or not base_url.strip():
            sys.stderr.write("error: [providers.%s] has no base_url\n" % quote_text(provider_id))
            return EXIT_CONFIG
        base_url = base_url.strip()
    else:
        if not candidates:
            sys.stderr.write("error: no [providers.*] with a base_url in %s\n" % config_path)
            return EXIT_CONFIG
        if len(candidates) > 1:
            sys.stderr.write(
                "error: several providers have a base_url; pass --provider with one of: %s\n"
                % ", ".join(quote_text(name) for name in candidates)
            )
            return EXIT_CONFIG
        provider_id = candidates[0]
        base_url = providers[provider_id]["base_url"].strip()

    provider_block = providers[provider_id]
    token = None
    env_name = provider_block.get("api_key_env")
    if isinstance(env_name, str) and env_name.strip():
        token = os.environ.get(env_name.strip()) or None
    if token is None:
        inline = provider_block.get("api_key")
        if isinstance(inline, str) and inline.strip():
            token = inline.strip()

    info_url = args.info_url or strip_trailing_v1(base_url) + "/model/info"
    origin = split_origin(base_url)

    rows = []
    catalog_warnings = []
    deadline = time.monotonic() + TOTAL_BUDGET
    try:
        catalog = read_catalog(base_url, info_url, token, deadline, catalog_warnings)
    except SyncError as error:
        sys.stderr.write("error: %s\n" % error)
        return error.code
    for warning in catalog_warnings:
        rows.append(row("aviso", provider_id, "(catálogo)", "—", "—", warning, warning=True))

    families_bytes = None
    families_changed = False
    families_candidate = None
    try:
        adds, sets = build_plan(config, catalog, provider_id, args.refresh_metadata, rows)

        families_adds = None
        families_expected = None
        families_text = None
        if args.refresh_families:
            if not os.path.isfile(families_path):
                rows.append(
                    row(
                        "aviso",
                        FAMILIES_GROUP,
                        families_path,
                        "—",
                        "—",
                        "no hay kimi-swarm.toml: ese archivo lo crea /kimi-swarm:setup, acá no se toca",
                        warning=True,
                    )
                )
            else:
                families_bytes = read_bytes(families_path)
                families_text = decode_text(families_bytes, families_path)
                families_config = parse_document(families_text, families_path)
                group_writes, new_group = build_families_plan(
                    config, families_config, catalog, provider_id, rows
                )
                families_expected = copy.deepcopy(families_config)
                families_expected["families"] = {}
                for group, aliases in families_config.get("families", {}).items():
                    families_expected["families"][group] = list(aliases)
                for group, aliases in group_writes:
                    families_expected["families"][group] = list(aliases)
                if new_group:
                    families_expected["families"][new_group[0]] = list(new_group[1])
                families_adds = (group_writes, new_group)

        expected = copy.deepcopy(config)
        expected["models"] = dict(expected.get("models") or {})
        for alias, block in adds:
            expected["models"][alias] = copy.deepcopy(block)
        for alias, field, value in sets:
            expected["models"][alias][field] = copy.deepcopy(value)

        candidate_text, catalog_changed = edit_models(
            original_text, expected, adds, sets, config_path
        )
        if families_adds is not None:
            families_candidate, families_changed = edit_families(
                families_text, families_expected, families_adds[0], families_adds[1], families_path
            )
    except SyncError as error:
        sys.stderr.write("error: %s\n" % error)
        return error.code

    warnings = [entry for entry in rows if entry["warning"]]
    payload = {
        "provider": provider_id,
        "origin": origin,
        "options": {
            "refresh_metadata": bool(args.refresh_metadata),
            "refresh_families": bool(args.refresh_families),
        },
        "config_sha256": sha256_bytes(original_bytes),
        "families_sha256": sha256_bytes(families_bytes) if families_bytes is not None else None,
        "changes": [
            {
                "action": entry["action"],
                "alias": entry["alias"],
                "field": entry["field"],
                "current": display(entry["current"]),
                "proposed": display(entry["proposed"]),
                "reason": entry["reason"],
            }
            for entry in rows
        ],
    }
    digest = plan_hash(payload)

    print("provider:  %s" % provider_id)
    print("origin:    %s" % origin)
    print("config:    %s" % config_path)
    if families_bytes is not None:
        print("families:  %s" % families_path)
    print("mode:      %s" % ("apply" if args.apply else "dry-run"))
    print("plan:      sha256:%s" % digest)
    print()
    if rows:
        print(render_table(rows))
    else:
        print("sin cambios: el catálogo ya refleja lo que el gateway anuncia")
    print()
    counts = count_actions(rows)
    if counts:
        print("resumen: %s" % ", ".join("%s=%d" % item for item in sorted(counts.items())))
    print("advertencias: %d" % len(warnings))

    change_count = len(adds) + len(sets) + (1 if families_changed else 0)
    if not args.apply:
        if change_count:
            print("dry run: no se escribió nada. Para aplicar: --apply --expect-plan sha256:%s" % digest)
        else:
            print("dry run: no hay nada para escribir")
        return EXIT_PARTIAL if warnings else EXIT_OK

    expected_digest = args.expect_plan.strip()
    if expected_digest.startswith("sha256:"):
        expected_digest = expected_digest[len("sha256:") :]
    if expected_digest != digest:
        sys.stderr.write(
            "error: the plan is not the one you confirmed (expected %s, current %s); nothing written\n"
            % (quote_text(expected_digest), digest)
        )
        return EXIT_LOCK

    if not change_count:
        print("nada para escribir: el catálogo ya refleja lo que el gateway anuncia")
        return EXIT_PARTIAL if warnings else EXIT_OK

    lock = FileLock(lock_path)
    if not lock.acquire():
        sys.stderr.write("error: another sync holds %s; nothing written\n" % lock_path)
        return EXIT_LOCK
    try:
        if sha256_bytes(read_bytes(config_path)) != payload["config_sha256"]:
            sys.stderr.write(
                "error: %s changed since the plan was built; nothing written\n" % config_path
            )
            return EXIT_LOCK
        families_mode = None
        if families_changed:
            if sha256_bytes(read_bytes(families_path)) != payload["families_sha256"]:
                sys.stderr.write(
                    "error: %s changed since the plan was built; nothing written\n" % families_path
                )
                return EXIT_LOCK
            families_mode = file_mode(families_path)

        try:
            if catalog_changed:
                print("backup:  %s" % backup_file(config_path))
                write_atomic(config_path, candidate_text, file_mode(config_path))
                print("escrito: %s" % config_path)
            if families_changed:
                families_backup = backup_file(families_path)
                print("backup:  %s" % families_backup)
                try:
                    write_atomic(families_path, families_candidate, families_mode)
                except OSError as error:
                    try:
                        shutil.copy2(families_backup, families_path)
                        os.chmod(families_path, families_mode)
                        restored = "restaurado desde %s" % families_backup
                    except OSError:
                        restored = "no se pudo restaurar; el backup queda en %s" % families_backup
                    sys.stderr.write(
                        "error: cannot write %s: %s (%s); el catálogo quedó aplicado\n"
                        % (families_path, error, restored)
                    )
                    return EXIT_WRITE
                print("escrito: %s" % families_path)
        except OSError as error:
            sys.stderr.write("error: cannot write: %s; nothing else was written\n" % error)
            return EXIT_WRITE
    finally:
        lock.release()

    if warnings:
        print(
            "parcial: se aplicaron los cambios seguros y quedaron %d advertencias; revisá la tabla"
            % len(warnings)
        )
        return EXIT_PARTIAL
    print("listo. corré /reload (o abrí una sesión nueva) en Kimi Code para aplicar")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
