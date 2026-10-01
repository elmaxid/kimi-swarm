#!/usr/bin/env python3
"""Confined execution helper for the security-audit skill.

Runs target-controlled code (builds, tests, fixtures, fuzzers) inside an
OS-enforced sandbox so a security audit can produce bounded local evidence
without exposing the host, its network, or its credentials.

Backends:
  systemd  systemd-run with DynamicUser + PrivateNetwork + ProtectSystem=strict
           (default on a systemd host; verified on Ubuntu with systemd 259)
  bwrap    bubblewrap namespace sandbox (any Linux, needs `apt install bubblewrap`)

Usage:
  swarm-sandbox.py create --out-dir DIR [--target PATH] [--backend systemd|bwrap]
  swarm-sandbox.py run --out-dir DIR --agent-id ID -c 'COMMAND'
  swarm-sandbox.py promote --out-dir DIR --agent-id ID --allow FILE
  swarm-sandbox.py status --out-dir DIR

Everything a target touches lives under DIR:
  DIR/run-metadata.json
  DIR/source/                 read-only copy of the target under test
  DIR/agents/<agent-id>/scratch/    the only writable location for the command
  DIR/agents/<agent-id>/artifacts/  parent-owned; fed only by `promote`

Put the run directory on a real filesystem (for example /opt or /srv). Do not
put it under /tmp or /var/tmp: systemd's DynamicUser namespace setup shadows
those paths, and `ReadWritePaths` on a shadowed path fails with
226/NAMESPACE.
"""

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys

AGENT_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
WINDOWS_RESERVED = {
    "con", "prn", "aux", "nul", "clock$", "conin$", "conout$",
    *(f"com{n}" for n in range(1, 10)),
    *(f"lpt{n}" for n in range(1, 10)),
}
SHADOWED_PREFIXES = ("/tmp/", "/var/tmp/")
MAX_PROMOTED_BYTES = 16 * 1024 * 1024
DEFAULT_MEMORY = "512M"
DEFAULT_TASKS = 64
DEFAULT_RUNTIME_S = 300

# Names never copied into the read-only source, so an audit run cannot leak the
# operator's secrets into its own artifacts. Override with --no-default-excludes.
DEFAULT_EXCLUDES = (
    "configs", "data", "caddy", ".tools", ".git", ".env",
    "host_key", "secrets.txt", "secret.key",
)
SECRET_SUFFIXES = (".key", ".pem", ".crt")
SECRET_NAMES = ("host_key", "secret.key", "secrets.txt", ".env")

# Fixed shell wrapper: the caller's command travels in an environment variable,
# so nothing from the command text is interpolated into the outer shell string.
WRAPPER = 'cd "$SWARM_WORKDIR" && eval "$SWARM_COMMAND"'

def fail(message):
    sys.stderr.write("error: %s\n" % message)
    return 1


def which(name):
    return shutil.which(name)


def validate_agent_id(agent_id):
    if not AGENT_ID_PATTERN.match(agent_id or ""):
        raise ValueError("agent id must match ^[a-z0-9][a-z0-9_-]{0,63}$")
    if agent_id in WINDOWS_RESERVED:
        raise ValueError("agent id must not be a reserved device name")
    return agent_id


def safe_path_segment(value):
    """Reject anything that could turn a declared file name into another path."""
    if not isinstance(value, str) or not value or value != value.strip():
        return False
    if value in (".", "..") or "\x00" in value:
        return False
    return not re.search(r"[/\\:]", value)


def resolve_out_dir(path):
    resolved = os.path.realpath(path)
    if resolved in ("/", os.path.expanduser("~")):
        raise ValueError("output dir must not be the filesystem root or the home directory")
    for prefix in SHADOWED_PREFIXES:
        if (resolved + "/").startswith(prefix):
            raise ValueError(
                "output dir must not live under /tmp or /var/tmp: the sandbox shadows those "
                "paths. Use a real filesystem location such as /opt or /srv.")
    return resolved


def agent_root(out_dir, agent_id):
    return os.path.join(out_dir, "agents", validate_agent_id(agent_id))


def scratch_dir(out_dir, agent_id):
    return os.path.join(agent_root(out_dir, agent_id), "scratch")


def artifacts_dir(out_dir, agent_id):
    return os.path.join(agent_root(out_dir, agent_id), "artifacts")


def metadata_path(out_dir):
    return os.path.join(out_dir, "run-metadata.json")


def load_metadata(out_dir):
    path = metadata_path(out_dir)
    if not os.path.exists(path):
        raise ValueError("no run-metadata.json in %s (run `create` first)" % out_dir)
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def save_metadata(out_dir, data):
    with open(metadata_path(out_dir), "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, sort_keys=True)
        handle.write("\n")


def detect_backend(requested):
    if requested and requested != "auto":
        return requested
    if which("systemd-run"):
        return "systemd"
    if which("bwrap"):
        return "bwrap"
    return None


def backend_available(backend):
    if backend == "systemd":
        return which("systemd-run") is not None
    if backend == "bwrap":
        return which("bwrap") is not None
    return False


def scan_source_for_secrets(source_dir):
    """List secret-looking files that made it into the read-only source copy."""
    found = []
    for root, dirs, files in os.walk(source_dir):
        for name in files:
            if name in SECRET_NAMES or name.lower().endswith(SECRET_SUFFIXES):
                found.append(os.path.relpath(os.path.join(root, name), source_dir))
    return sorted(found)


def make_traversable(path):
    """Let an ephemeral sandbox user read its way into the run directory."""
    current = path
    while True:
        try:
            mode = os.stat(current).st_mode & 0o777
            os.chmod(current, mode | 0o755)
        except OSError:
            pass
        parent = os.path.dirname(current)
        if parent == current or current == "/":
            break
        current = parent
        if current in ("/", "/opt", "/srv", "/home", "/var"):
            break


def cmd_create(args):
    try:
        out_dir = resolve_out_dir(args.out_dir)
    except ValueError as error:
        return fail(str(error))

    backend = detect_backend(args.backend)
    if backend is None:
        return fail("no sandbox backend found: install systemd-run (systemd) or bubblewrap (bwrap)")
    if not backend_available(backend):
        return fail("requested backend %r is not available on this host" % backend)

    os.makedirs(out_dir, exist_ok=True)

    source_dir = os.path.join(out_dir, "source")
    if args.target:
        target = os.path.realpath(args.target)
        if not os.path.isdir(target):
            return fail("--target is not a directory: %s" % args.target)
        if os.path.exists(source_dir):
            shutil.rmtree(source_dir)

        excludes = [name for name in (args.exclude or []) if name]
        if not args.no_default_excludes:
            excludes += [name for name in DEFAULT_EXCLUDES if name not in excludes]
        exclude_set = set(excludes)

        def ignore(directory, names):
            skipped = [name for name in names if name in exclude_set]
            return skipped

        shutil.copytree(target, source_dir, symlinks=False,
                        ignore_dangling_symlinks=True, ignore=ignore)
        metadata_excludes = sorted(exclude_set)

    metadata = load_metadata(out_dir) if os.path.exists(metadata_path(out_dir)) else {}
    if args.target:
        metadata["excluded_names"] = metadata_excludes
        leaked = scan_source_for_secrets(source_dir)
        metadata["secret_files_in_source"] = leaked
    metadata.update({
        "run_id": os.path.basename(out_dir),
        "out_dir": out_dir,
        "source_dir": source_dir if os.path.isdir(source_dir) else None,
        "target": os.path.realpath(args.target) if args.target else None,
        "backend": backend,
        "execution_policy": "sandboxed-local-only",
        "sandbox_controls": {
            "network": "none",
            "user": "ephemeral",
            "home": "empty (set to scratch)",
            "system": "read-only",
            "writable": "agent scratch only",
            "limits": {
                "memory": DEFAULT_MEMORY,
                "tasks": DEFAULT_TASKS,
                "runtime_seconds": DEFAULT_RUNTIME_S,
            },
        },
    })
    save_metadata(out_dir, metadata)

    print("created %s" % out_dir)
    print("backend: %s" % backend)
    if metadata["source_dir"]:
        print("source copy: %s" % metadata["source_dir"])
        print("excluded: %s" % ", ".join(metadata.get("excluded_names", [])))
        leaked = metadata.get("secret_files_in_source", [])
        if leaked:
            shown = ", ".join(leaked[:10])
            more = "" if len(leaked) <= 10 else ", ... and %d more" % (len(leaked) - 10)
            print("WARNING: %d secret-looking file(s) copied into the source:" % len(leaked))
            print("         %s%s" % (shown, more))
            print("         re-run with more --exclude, or check the target's ignore rules")
    print("run with: %s run --out-dir %s --agent-id <id> -c '<command>'"
          % (os.path.basename(__file__), shlex.quote(out_dir)))
    return 0


def build_systemd_command(workdir, command, scratch, memory, tasks, runtime_s, source=None):
    argv = [
        "systemd-run", "--quiet", "--wait", "--collect", "--pipe",
        "-p", "DynamicUser=yes",
        "-p", "PrivateNetwork=yes",
        "-p", "ProtectSystem=strict",
        "-p", "ProtectHome=yes",
        "-p", "NoNewPrivileges=yes",
        "-p", "ReadWritePaths=%s" % scratch,
        "-p", "MemoryMax=%s" % memory,
        "-p", "TasksMax=%s" % tasks,
        "-p", "RuntimeMaxSec=%s" % runtime_s,
        "--setenv=HOME=%s" % scratch,
        "--setenv=TMPDIR=%s" % scratch,
        "--setenv=SWARM_WORKDIR=%s" % workdir,
        "--setenv=SWARM_COMMAND=%s" % command,
    ]
    if source:
        # The command can copy the read-only source into the writable scratch and
        # work on the copy, which is how a build that writes beside source runs.
        argv.append("--setenv=SWARM_SOURCE=%s" % source)
    argv += ["/bin/sh", "-c", WRAPPER]
    return argv


def build_bwrap_command(workdir, command, scratch):
    source = None
    argv = [
        "bwrap", "--unshare-all", "--die-with-parent",
        "--proc", "/proc", "--dev", "/dev",
        "--ro-bind", "/usr", "/usr",
    ]
    for extra in ("/lib", "/lib64", "/bin", "/sbin", "/etc"):
        if os.path.isdir(extra):
            argv += ["--ro-bind", extra, extra]
    argv += ["--bind", scratch, scratch]
    argv += [
        "--tmpfs", "/tmp",
        "--setenv", "HOME", scratch,
        "--setenv", "TMPDIR", scratch,
        "--chdir", workdir,
        "/bin/sh", "-c", command,
    ]
    return argv


def cmd_run(args):
    try:
        out_dir = resolve_out_dir(args.out_dir)
        agent_id = validate_agent_id(args.agent_id)
        metadata = load_metadata(out_dir)
    except ValueError as error:
        return fail(str(error))

    backend = metadata.get("backend")
    if backend not in ("systemd", "bwrap"):
        return fail("unknown backend in metadata: %r" % backend)

    scratch = scratch_dir(out_dir, agent_id)
    artifacts = artifacts_dir(out_dir, agent_id)
    os.makedirs(scratch, exist_ok=True)
    os.makedirs(artifacts, exist_ok=True)
    make_traversable(out_dir)
    if backend == "systemd":
        # DynamicUser is ephemeral, so it is never the owner of scratch.
        os.chmod(scratch, 0o1777)
    os.chmod(artifacts, 0o700)

    source_dir = metadata.get("source_dir")
    if args.workdir == "scratch" or not source_dir or not os.path.isdir(source_dir):
        workdir = scratch
    else:
        workdir = source_dir

    limits = metadata.get("sandbox_controls", {}).get("limits", {})
    memory = limits.get("memory", DEFAULT_MEMORY)
    tasks = str(limits.get("tasks", DEFAULT_TASKS))
    runtime_s = str(limits.get("runtime_seconds", DEFAULT_RUNTIME_S))

    if backend == "systemd":
        argv = build_systemd_command(workdir, args.command, scratch, memory, tasks, runtime_s,
                                     source_dir)
    else:
        argv = build_bwrap_command(workdir, args.command, scratch)

    completed = subprocess.run(argv)
    return completed.returncode


def safe_relative_file_path(value):
    """A relative, non-empty path whose every segment is a plain name."""
    if not isinstance(value, str) or not value or "\\" in value or ":" in value:
        return False
    if value.startswith("/") or value.startswith("~"):
        return False
    segments = value.split("/")
    return all(safe_path_segment(segment) for segment in segments)


def cmd_promote(args):
    try:
        out_dir = resolve_out_dir(args.out_dir)
        agent_id = validate_agent_id(args.agent_id)
    except ValueError as error:
        return fail(str(error))

    allow = args.allow or []
    if not allow:
        return fail("promote requires at least one --allow FILE")

    scratch = scratch_dir(out_dir, agent_id)
    artifacts = artifacts_dir(out_dir, agent_id)
    os.makedirs(artifacts, exist_ok=True)

    promoted = []
    for name in allow:
        if not safe_relative_file_path(name):
            return fail("--allow must be a relative path inside scratch: %r" % name)
        source = os.path.join(scratch, name)
        if os.path.islink(source):
            return fail("refusing to promote a symlink: %s" % name)
        if not os.path.isfile(source):
            return fail("not a regular file in scratch: %s" % name)
        size = os.path.getsize(source)
        if size > MAX_PROMOTED_BYTES:
            return fail("refusing to promote %s: %d bytes exceeds %d"
                        % (name, size, MAX_PROMOTED_BYTES))
        destination = os.path.join(artifacts, name)
        if os.path.lexists(destination):
            return fail("refusing to overwrite existing artifact: %s" % name)
        os.makedirs(os.path.dirname(destination), exist_ok=True)
        shutil.copyfile(source, destination)
        os.chmod(destination, 0o600)
        promoted.append(name)

    print("promoted %d file(s) into %s" % (len(promoted), artifacts))
    for name in promoted:
        print("  %s" % os.path.join(artifacts, name))
    return 0


def cmd_status(args):
    try:
        out_dir = resolve_out_dir(args.out_dir)
        metadata = load_metadata(out_dir)
    except ValueError as error:
        return fail(str(error))
    print(json.dumps(metadata, indent=2, sort_keys=True))
    return 0


def build_parser():
    parser = argparse.ArgumentParser(description="Confined execution helper for security audits")
    sub = parser.add_subparsers(dest="command", required=True)

    create = sub.add_parser("create", help="set up a run directory and its sandbox")
    create.add_argument("--out-dir", required=True)
    create.add_argument("--target", help="repository to copy into the run as read-only source")
    create.add_argument("--exclude", action="append", default=[],
                        help="directory or file name to omit from the source copy, at any depth "
                             "(repeatable); use for secret-bearing paths")
    create.add_argument("--no-default-excludes", action="store_true",
                        help="do not apply the built-in secret-directory excludes "
                             "(configs, data, caddy, .tools, .git, .env, keys)")
    create.add_argument("--backend", default="auto", choices=["auto", "systemd", "bwrap"])
    create.set_defaults(func=cmd_create)

    run = sub.add_parser("run", help="run a command confined to an agent's scratch")
    run.add_argument("--out-dir", required=True)
    run.add_argument("--agent-id", required=True)
    run.add_argument("-c", "--command", required=True)
    run.add_argument("--workdir", choices=["source", "scratch"], default="source",
                     help="working directory: read-only source copy (default) or the writable scratch")
    run.set_defaults(func=cmd_run)

    promote = sub.add_parser("promote", help="copy verified scratch files into parent-owned artifacts")
    promote.add_argument("--out-dir", required=True)
    promote.add_argument("--agent-id", required=True)
    promote.add_argument("--allow", action="append", default=[],
                         help="bare file name inside scratch to promote (repeatable)")
    promote.set_defaults(func=cmd_promote)

    status = sub.add_parser("status", help="print the run metadata")
    status.add_argument("--out-dir", required=True)
    status.set_defaults(func=cmd_status)

    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
