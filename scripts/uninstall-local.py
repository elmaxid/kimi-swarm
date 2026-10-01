#!/usr/bin/env python3
"""Uninstall this plugin from the local Kimi Code home.

Undoes what install-local.py did, and nothing else:

  default          remove the plugin's entry from plugins/installed.json
  --purge          also delete the managed copy under plugins/managed/<id>/
  --remove-pool    also strip the [secondary_model] section from config.toml
                     (a timestamped backup is written first)
  --restore-backup also replace config.toml with a backup you name explicitly
  --dry-run        print the plan and change nothing

It never touches the plugin source tree, and never edits any other part of
config.toml: --remove-pool removes exactly the [secondary_model] section.

Usage:
  uninstall-local.py [--home DIR] [--name ID] [--purge] [--remove-pool] [--dry-run]
  uninstall-local.py --restore-backup ~/.kimi-code/config.toml.20260101-120000.bak
"""

import argparse
import json
import os
import shutil
import sys
from datetime import datetime, timezone


def resolve_home(explicit):
    if explicit:
        return os.path.realpath(explicit)
    env = os.environ.get("KIMI_CODE_HOME")
    if env:
        return os.path.realpath(env)
    return os.path.join(os.path.expanduser("~"), ".kimi-code")


def strip_section(text, name):
    """Remove the [name] table and its subsections; return (text, removed)."""
    lines = text.splitlines(keepends=True)
    start = None
    for index, line in enumerate(lines):
        if line.strip() == "[%s]" % name:
            start = index
            break
    if start is None:
        return text, False

    end = len(lines)
    for index in range(start + 1, len(lines)):
        stripped = lines[index].lstrip()
        if stripped.startswith("[") and stripped.rstrip().endswith("]"):
            if not stripped.startswith("[%s" % name):
                end = index
                break

    begin = start
    if begin > 0 and lines[begin - 1].strip() == "":
        begin -= 1
    return "".join(lines[:begin] + lines[end:]), True


def backup_file(path):
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    backup = "%s.%s.bak" % (path, stamp)
    shutil.copy2(path, backup)
    return backup


def load_registry(path):
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Uninstall a Kimi Code plugin locally")
    parser.add_argument("--home", help="KIMI_CODE_HOME (default: $KIMI_CODE_HOME or ~/.kimi-code)")
    parser.add_argument("--name", default="kimi-swarm", help="plugin id (default: kimi-swarm)")
    parser.add_argument("--purge", action="store_true", help="also delete the managed copy")
    parser.add_argument("--remove-pool", action="store_true",
                        help="also remove the [secondary_model] section from config.toml")
    parser.add_argument("--restore-backup", metavar="FILE",
                        help="replace config.toml with this backup file (instead of --remove-pool)")
    parser.add_argument("--dry-run", action="store_true", help="print the plan, change nothing")
    args = parser.parse_args(argv)

    home = resolve_home(args.home)
    plugin_id = args.name
    plugins_dir = os.path.join(home, "plugins")
    registry_path = os.path.join(plugins_dir, "installed.json")
    managed = os.path.join(plugins_dir, "managed", plugin_id)
    config_path = os.path.join(home, "config.toml")

    actions = []
    skipped = []

    registry = load_registry(registry_path)
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
        actions.append("replace %s with %s (backing up the current file first)"
                       % (config_path, restore))
    elif args.remove_pool:
        if not os.path.isfile(config_path):
            skipped.append("no config.toml at %s" % config_path)
        else:
            with open(config_path, "r", encoding="utf-8") as handle:
                _, removed = strip_section(handle.read(), "secondary_model")
            if removed:
                actions.append("remove the [secondary_model] section from %s" % config_path)
            else:
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
        print("backup: %s" % backup_file(config_path))
        shutil.copy2(restore, config_path)
        print("restored %s from %s" % (config_path, restore))
    elif args.remove_pool and os.path.isfile(config_path):
        with open(config_path, "r", encoding="utf-8") as handle:
            original = handle.read()
        updated, removed = strip_section(original, "secondary_model")
        if removed:
            print("backup: %s" % backup_file(config_path))
            with open(config_path, "w", encoding="utf-8") as handle:
                handle.write(updated)
            print("removed the [secondary_model] section from %s" % config_path)

    print("done. run /reload (or start a new session) in Kimi Code to apply")
    for note in skipped:
        print("  kept: %s" % note)
    return 0


if __name__ == "__main__":
    sys.exit(main())
