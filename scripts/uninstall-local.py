#!/usr/bin/env python3
"""Uninstall this plugin from the local Kimi Code home.

Undoes what install-local.py did, and nothing else:

  default          remove the plugin's entry from plugins/installed.json
  --purge          also delete the managed copy under plugins/managed/<id>/
  --remove-pool    also strip the [secondary_model] section from config.toml
                     (a timestamped backup is written first)
  --restore-backup also replace config.toml with a backup you name explicitly
  --dry-run        print the plan and change nothing

It never touches the plugin source tree. --remove-pool removes the
[secondary_model] table, its [secondary_model.*] subsections and the comment
block directly above the header (plus one blank line when no comment block
precedes it); a comment block that documents the *next* table stays with that
table. The rest of config.toml is left byte-for-byte untouched, including a
leading UTF-8 BOM.

Before anything is written, the original and the result are both parsed with
tomllib (BOM stripped from both) and compared structurally: every table other
than [secondary_model] must be deeply equal. If the original does not parse, or
the result would drop anything else, nothing is written.

Usage:
  uninstall-local.py [--home DIR] [--name ID] [--purge] [--remove-pool] [--dry-run]
  uninstall-local.py --restore-backup ~/.kimi-code/config.toml.20260101-120000.bak
"""

import argparse
import json
import os
import re
import shutil
import stat
import sys
import tomllib
from datetime import datetime, timezone

ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def resolve_home(explicit):
    if explicit:
        return os.path.realpath(explicit)
    env = os.environ.get("KIMI_CODE_HOME")
    if env:
        return os.path.realpath(env)
    return os.path.realpath(os.path.join(os.path.expanduser("~"), ".kimi-code"))


def validate_id(plugin_id):
    if not isinstance(plugin_id, str) or plugin_id in (".", "..") or not ID_PATTERN.match(plugin_id):
        raise ValueError("invalid plugin id %r: must match ^[A-Za-z0-9][A-Za-z0-9._-]*$" % (plugin_id,))
    return plugin_id


def path_contains(parent, child):
    """True when the resolved child path is the parent or lies under it."""
    if parent == child:
        return True
    try:
        return os.path.commonpath([parent, child]) == parent
    except ValueError:
        return False


def _skip_quoted(line, index):
    """Return the index just past the single-line string starting at index.

    Single-line TOML strings cannot span lines, so an unterminated one ends at
    end of line instead of leaking its state into the following lines.
    """
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
    """Return the dotted segments of a TOML header line, or None.

    Segments are split on the dots that are outside quoted keys, and each
    segment is unquoted, so ``["secondary_model.x"]`` (a single key whose name
    contains a dot) is not confused with ``["secondary_model".x]`` (a genuine
    subtable of secondary_model).
    """
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
    """Lex each physical line and return one record per line.

    A record is ``(continued, code, depth)`` where ``continued`` marks a line
    that starts inside a ``\"\"\"``/``'''`` multiline string, ``code`` is the
    line with any trailing comment removed, and ``depth`` is the bracket
    nesting depth outside strings at the start of the line. The scanner walks
    each line character by character through the code, string, multiline
    string and comment states, so a lone ``\"\"\"`` or ``'''`` inside a quoted
    scalar or a comment never opens a multiline string. Only the TOML newline
    (LF or CRLF) starts a new line: str.splitlines would also break on form
    feed, NEL and U+2028/U+2029, which TOML accepts inside comments.
    """
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


def _is_comment_line(record, line):
    continued, _code, _depth = record
    return not continued and line.strip().startswith("#")


def strip_section(text, name):
    """Remove the [name] table, its subsections and the comment block above it.

    Returns (updated_text, removed). The header may carry inner whitespace, a
    trailing comment, or a quoted spelling such as ['secondary_model'], and a
    leading UTF-8 BOM is preserved. Headers inside comments, TOML multiline
    strings or multi-line arrays are ignored, and a subsection declared before
    its parent header is removed with it, as is a header with spaces around the
    dot ([ secondary_model . sub ]). A table whose name only looks like a
    subtable, such as ["secondary_model.x"], is a different key and is left
    alone. If no header line is found but the parsed file does have that key
    (dotted keys or an inline table), the removal raises instead of reporting
    success, and a plain scalar value of that name is refused the same way.

    Before returning, the BOM-stripped original and the BOM-stripped candidate
    are both parsed with tomllib and compared: every table other than [name]
    must be deeply equal and no other top-level key may disappear. The removal
    is therefore verified structurally rather than by merely re-parsing the
    result, and it fails closed instead of truncating the file.
    """
    bom = ""
    body = text
    if body.startswith("\ufeff"):
        bom, body = "\ufeff", body[1:]

    try:
        original = tomllib.loads(body)
    except tomllib.TOMLDecodeError as error:
        raise ValueError("config.toml does not parse, refusing to edit it: %s" % error)

    lines = re.split(r"(?<=\n)", body)
    records = _scan_lines(body)
    if lines and lines[-1] == "":
        # re.split keeps a trailing empty sentinel that splitlines did not, and
        # it would hide the last real line from the comment back-off below.
        lines.pop()
        records.pop()

    def boundary_parts(index):
        """Dotted segments of a real header at index, or None if not a header."""
        continued, code, depth = records[index]
        if continued or depth != 0 or not code.lstrip().startswith("["):
            return None
        return _header_parts(code)

    def in_section(parts):
        """True when a header names the target table or one of its subtables."""
        return parts[0] == name

    start = None
    for index in range(len(lines)):
        parts = boundary_parts(index)
        if parts is not None and in_section(parts):
            start = index
            break
    if start is None:
        if name in original:
            shape = ("an inline table or dotted keys" if isinstance(original[name], dict)
                     else "a plain %s value" % type(original[name]).__name__)
            raise ValueError(
                "[%s] has no header line: it is defined as %s, which this tool does not "
                "rewrite; remove it by hand" % (name, shape))
        return text, False

    end = len(lines)
    for index in range(start + 1, len(lines)):
        _continued, code, depth = records[index]
        if _continued or depth != 0 or not code.lstrip().startswith("["):
            continue
        parts = boundary_parts(index)
        if parts is not None and in_section(parts):
            continue
        end = index
        break

    while end - 1 > start and _is_comment_line(records[end - 1], lines[end - 1]):
        end -= 1

    begin = start
    while begin > 0 and _is_comment_line(records[begin - 1], lines[begin - 1]):
        begin -= 1
    if begin == start and begin > 0 and lines[begin - 1].strip() == "":
        begin -= 1

    candidate = "".join(lines[:begin] + lines[end:])
    try:
        updated = tomllib.loads(candidate)
    except tomllib.TOMLDecodeError as error:
        raise ValueError("updated config.toml would not parse: %s" % error)

    expected = {key: value for key, value in original.items() if key != name}
    if updated != expected:
        lost = sorted(set(expected) - set(updated))
        extra = sorted(set(updated) - set(expected))
        detail = "lost %s" % ", ".join(lost) if lost else "unexpected change"
        if extra:
            detail += "; gained %s" % ", ".join(extra)
        raise ValueError("refusing to remove [%s]: the rest of config.toml would change (%s)"
                         % (name, detail))
    return bom + candidate, True


def backup_file(path):
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    backup = "%s.%s.bak" % (path, stamp)
    if os.path.realpath(backup) != os.path.realpath(path):
        os.makedirs(os.path.dirname(backup) or ".", exist_ok=True)
        shutil.copy2(path, backup)
    return backup


def load_registry(path):
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as handle:
        try:
            data = json.load(handle)
        except ValueError as error:
            raise ValueError("%s is not valid JSON: %s" % (path, error))
    if not isinstance(data, dict) or not isinstance(data.get("plugins"), list):
        raise ValueError("%s is not a valid InstalledFile" % path)
    return data


def main(argv=None):
    parser = argparse.ArgumentParser(description="Uninstall a Kimi Code plugin locally")
    parser.add_argument("--home", help="KIMI_CODE_HOME (default: $KIMI_CODE_HOME or ~/.kimi-code)")
    parser.add_argument("--name", default="kimi-swarm", help="plugin id (default: kimi-swarm)")
    parser.add_argument("--purge", action="store_true", help="also delete the managed copy")
    config_group = parser.add_mutually_exclusive_group()
    config_group.add_argument("--remove-pool", action="store_true",
                              help="also remove the [secondary_model] section from config.toml")
    config_group.add_argument("--restore-backup", metavar="FILE",
                              help="replace config.toml with this backup file (instead of --remove-pool)")
    parser.add_argument("--dry-run", action="store_true", help="print the plan, change nothing")
    args = parser.parse_args(argv)

    home = resolve_home(args.home)
    try:
        plugin_id = validate_id(args.name)
    except ValueError as error:
        sys.stderr.write("error: %s\n" % error)
        return 1
    plugins_dir = os.path.join(home, "plugins")
    registry_path = os.path.join(plugins_dir, "installed.json")
    managed = os.path.join(plugins_dir, "managed", plugin_id)
    config_path = os.path.join(home, "config.toml")

    managed_parent = os.path.join(plugins_dir, "managed")
    if os.path.islink(managed_parent):
        sys.stderr.write("error: refusing to act through a symlinked plugins/managed: %s -> %s\n"
                         % (managed_parent, os.path.realpath(managed_parent)))
        return 1
    resolved_parent = os.path.realpath(managed_parent)
    if os.path.islink(managed):
        sys.stderr.write("error: refusing to use a symlinked managed copy: %s -> %s\n"
                         % (managed, os.path.realpath(managed)))
        return 1
    resolved_managed = os.path.realpath(managed)
    if os.path.dirname(resolved_managed) != resolved_parent or not path_contains(home, resolved_managed):
        sys.stderr.write("error: refusing to use a managed path outside %s: %s\n"
                         % (resolved_parent, managed))
        return 1

    actions = []
    skipped = []
    pool_update = None

    try:
        registry = load_registry(registry_path)
    except ValueError as error:
        sys.stderr.write("error: %s\n" % error)
        return 1
    if registry is None:
        skipped.append("registry not found: %s" % registry_path)
    else:
        plugins = registry.get("plugins", [])
        if any(entry.get("id") == plugin_id for entry in plugins):
            actions.append("remove the %r entry from %s" % (plugin_id, registry_path))
        else:
            skipped.append("%r is not registered in %s" % (plugin_id, registry_path))

    if args.purge:
        if os.path.isdir(managed):
            actions.append("delete the managed copy %s" % managed)
        else:
            skipped.append("no managed copy at %s" % managed)
    else:
        skipped.append("managed copy kept at %s (pass --purge to delete it)" % managed)

    restore = None
    if args.restore_backup:
        restore = os.path.realpath(os.path.expanduser(args.restore_backup))
        if not os.path.isfile(restore):
            sys.stderr.write("error: backup file not found: %s\n" % restore)
            return 1
        if os.path.realpath(config_path) == restore:
            sys.stderr.write("error: backup file is config.toml itself: %s\n" % restore)
            return 1
        actions.append("replace %s with %s (backing up the current file first)"
                       % (config_path, restore))
    elif args.remove_pool:
        if not os.path.isfile(config_path):
            skipped.append("no config.toml at %s" % config_path)
        else:
            try:
                with open(config_path, "r", encoding="utf-8", newline="") as handle:
                    pool_update, removed = strip_section(handle.read(), "secondary_model")
            except (OSError, ValueError) as error:
                sys.stderr.write("error: %s\n" % error)
                return 1
            if removed:
                actions.append("remove the [secondary_model] section from %s" % config_path)
            else:
                pool_update = None
                skipped.append("config.toml has no [secondary_model] section")
    else:
        skipped.append("config.toml left untouched (pass --remove-pool to strip the pool)")

    if not actions:
        print("nothing to do")
        for note in skipped:
            print("  - %s" % note)
        return 0

    print("plan:")
    for action in actions:
        print("  - %s" % action)
    if args.dry_run:
        print("dry run: no changes made")
        for note in skipped:
            print("  kept: %s" % note)
        return 0

    if registry is not None and any(e.get("id") == plugin_id for e in registry.get("plugins", [])):
        registry["plugins"] = [e for e in registry["plugins"] if e.get("id") != plugin_id]
        registry.setdefault("version", 1)
        with open(registry_path, "w", encoding="utf-8") as handle:
            json.dump(registry, handle, indent=2)
            handle.write("\n")
        print("unregistered %s from %s" % (plugin_id, registry_path))

    if args.purge and os.path.isdir(managed):
        shutil.rmtree(managed)
        print("deleted %s" % managed)

    if restore:
        mode = 0o600
        if os.path.isfile(config_path):
            mode = stat.S_IMODE(os.stat(config_path).st_mode)
            print("backup: %s" % backup_file(config_path))
        os.makedirs(os.path.dirname(config_path) or ".", exist_ok=True)
        shutil.copy2(restore, config_path)
        os.chmod(config_path, mode)
        print("restored %s from %s" % (config_path, restore))
    elif pool_update is not None:
        print("backup: %s" % backup_file(config_path))
        with open(config_path, "w", encoding="utf-8", newline="") as handle:
            handle.write(pool_update)
        print("removed the [secondary_model] section from %s" % config_path)

    print("done. run /reload (or start a new session) in Kimi Code to apply")
    for note in skipped:
        print("  kept: %s" % note)
    return 0


if __name__ == "__main__":
    sys.exit(main())
