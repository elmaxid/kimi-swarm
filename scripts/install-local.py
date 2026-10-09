#!/usr/bin/env python3
"""Install this plugin into the local Kimi Code home as a managed copy.

Copies the plugin into $KIMI_CODE_HOME/plugins/managed/<id>/ and records it in
$KIMI_CODE_HOME/plugins/installed.json, which is the registry Kimi Code reads.
The CLI runs from the managed copy, so re-run this script after editing the
source tree.

Usage:
  install-local.py [--source DIR] [--home DIR] [--name ID]

Defaults: --source is the plugin root containing this script's parent, --home is
$KIMI_CODE_HOME or ~/.kimi-code.
"""

import argparse
import json
import os
import re
import shutil
import sys
from datetime import datetime, timezone

SKIP = shutil.ignore_patterns(".git", "__pycache__", "*.pyc", "*.pyo")
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


def paths_overlap(first, second):
    """True when two resolved paths are equal or one contains the other."""
    if first == second:
        return True
    try:
        return os.path.commonpath([first, second]) in (first, second)
    except ValueError:
        return False


def load_manifest(source):
    path = os.path.join(source, "kimi.plugin.json")
    if not os.path.exists(path):
        raise ValueError("no kimi.plugin.json in %s" % source)
    with open(path, "r", encoding="utf-8") as handle:
        manifest = json.load(handle)
    if not manifest.get("name"):
        raise ValueError("kimi.plugin.json has no name")
    return manifest


def load_registry(path):
    if not os.path.exists(path):
        return {"version": 1, "plugins": []}
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict) or not isinstance(data.get("plugins"), list):
        raise ValueError("%s is not a valid InstalledFile" % path)
    return data


def main(argv=None):
    parser = argparse.ArgumentParser(description="Install a Kimi Code plugin locally")
    here = os.path.dirname(os.path.realpath(__file__))
    parser.add_argument("--source", default=os.path.dirname(here),
                        help="plugin root (default: the parent of this script)")
    parser.add_argument("--home", help="KIMI_CODE_HOME (default: $KIMI_CODE_HOME or ~/.kimi-code)")
    parser.add_argument("--name", help="plugin id (default: the manifest name)")
    args = parser.parse_args(argv)

    source = os.path.realpath(args.source)
    try:
        manifest = load_manifest(source)
    except ValueError as error:
        sys.stderr.write("error: %s\n" % error)
        return 1

    try:
        plugin_id = validate_id(args.name or manifest["name"])
    except ValueError as error:
        sys.stderr.write("error: %s\n" % error)
        return 1

    home = resolve_home(args.home)
    plugins_dir = os.path.join(home, "plugins")
    managed = os.path.join(plugins_dir, "managed", plugin_id)
    registry_path = os.path.join(plugins_dir, "installed.json")

    managed_parent = os.path.join(plugins_dir, "managed")
    if os.path.islink(managed_parent):
        sys.stderr.write("error: refusing to install through a symlinked plugins/managed: %s -> %s\n"
                         % (managed_parent, os.path.realpath(managed_parent)))
        return 1

    try:
        registry = load_registry(registry_path)
    except ValueError as error:
        sys.stderr.write("error: %s\n" % error)
        return 1

    os.makedirs(managed_parent, exist_ok=True)
    resolved_parent = os.path.realpath(managed_parent)
    if os.path.islink(managed):
        destination = os.path.join(resolved_parent, plugin_id)
    else:
        destination = os.path.realpath(managed)
    if os.path.dirname(destination) != resolved_parent:
        sys.stderr.write("error: refusing to write outside the managed plugins dir: %s\n" % managed)
        return 1
    if paths_overlap(source, destination):
        sys.stderr.write("error: source %s overlaps the managed copy %s; "
                         "run the installer from the plugin source tree, not from the managed copy\n"
                         % (source, destination))
        return 1

    if os.path.islink(managed) or (os.path.exists(managed) and not os.path.isdir(managed)):
        os.unlink(managed)
    if os.path.isdir(managed):
        shutil.rmtree(managed)
    shutil.copytree(source, managed, ignore=SKIP, symlinks=True)

    record = {
        "id": plugin_id,
        "root": managed,
        "source": "local-path",
        "enabled": True,
        "installedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "originalSource": source,
    }
    registry["plugins"] = [r for r in registry["plugins"] if r.get("id") != plugin_id] + [record]
    registry.setdefault("version", 1)

    os.makedirs(plugins_dir, exist_ok=True)
    with open(registry_path, "w", encoding="utf-8") as handle:
        json.dump(registry, handle, indent=2)
        handle.write("\n")

    print("installed %s -> %s" % (plugin_id, managed))
    print("registry:  %s" % registry_path)
    print("now run /reload (or start a new session) in Kimi Code to activate it")
    return 0


if __name__ == "__main__":
    sys.exit(main())
