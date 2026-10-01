#!/usr/bin/env python3
"""Differential test: Python port vs the Node oracle.

For a corpus of inputs, run both the Node validator (via the portable oracle)
and the Python validator and compare exit code, stdout and the full stderr
text byte for byte.

Usage: python3 differential_test.py
"""

import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
NODE = "/tmp/oracle-node/bin/node"
PYTHON = sys.executable
FINDINGS_CJS = os.path.join(HERE, "validate-findings.cjs")
FINDINGS_PY = os.path.join(HERE, "validate-findings.py")
LEDGER_CJS = os.path.join(HERE, "validate-coverage-ledger.cjs")
LEDGER_PY = os.path.join(HERE, "validate-coverage-ledger.py")


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, filename))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


fixtures = _load("test_validators", "test_validators.py")
js_json = fixtures.js_json

TERMINAL_CONTROL_PAYLOAD = fixtures.TERMINAL_CONTROL_PAYLOAD
HOSTILE = "\u001b\u0007\u0085\u202e\u034f\ufe0f\u00ad\u200b\ud800\udc00"


def content_cases():
    findings = []
    ledger = []

    def add_findings(name, value):
        findings.append((name, js_json(value)))

    def add_findings_raw(name, text):
        findings.append((name, text))

    def add_ledger(name, value):
        ledger.append((name, js_json(value)))

    def add_ledger_raw(name, text):
        ledger.append((name, text))

    # ---- findings: valid documents ----
    add_findings("valid-empty", [])
    add_findings("valid-all-branches", [fixtures.confirmed(), fixtures.needs_validation(), fixtures.rejected()])
    add_findings("valid-producer-shaped", fixtures.producer_shaped_findings())

    local_only = fixtures.needs_validation()
    del local_only["validation_plan"]["deployment"]
    add_findings("valid-local-plan-only", [local_only])
    deployment_only = fixtures.needs_validation()
    del deployment_only["validation_plan"]["local"]
    add_findings("valid-deployment-plan-only", [deployment_only])

    one_line = fixtures.confirmed()
    one_line["trace"] = [fixtures.source("entrypoint")]
    add_findings("valid-one-line-trace", [one_line])

    unicode_finding = fixtures.confirmed()
    unicode_finding["title"] = "Finding \U0001f600 cafe\u0301"
    unicode_finding["trace"][0]["file"] = "src/\u65e5\u672c\u8a9e/cafe\u0301-\U0001f600.ts"
    unicode_finding["remediation"]["code_changes"] = [{"file_name": "src/\u4fee\u6b63/\u00e9xito.ts", "fixed_code": "x"}]
    add_findings("valid-unicode", [unicode_finding])

    # ---- findings: invalid mutations ----
    for label, mutate in [
        ("empty-title", lambda f: f.update(title="")),
        ("blank-title", lambda f: f.update(title="   ")),
        ("empty-evidence", lambda f: f.update(evidence=[])),
        ("empty-payloads", lambda f: f["execution"].update(payloads=[])),
        ("empty-instructions", lambda f: f["execution"].update(instructions=[])),
        ("empty-observed", lambda f: f["execution"].update(observed_result="")),
        ("empty-strategy", lambda f: f["remediation"].update(strategy="")),
        ("line-zero", lambda f: f["trace"][0].update(line=0)),
        ("bad-path", lambda f: f["trace"][0].update(file="/etc/passwd")),
        ("bad-kind", lambda f: f["trace"][0].update(kind="invalid")),
        ("severity-above-impact", lambda f: (f["severity"].update(overall_severity="high"), f["severity"]["impact"].update(score="low"))),
        ("extra-field", lambda f: f.update(constructor="nope")),
        ("bad-fingerprint", lambda f: f.update(fingerprint="not stable")),
        ("missing-field", lambda f: f.pop("title")),
        ("control-kind", lambda f: f["trace"][0].update(kind="invalid-" + TERMINAL_CONTROL_PAYLOAD)),
        ("control-path", lambda f: f["trace"][0].update(file="src/file" + TERMINAL_CONTROL_PAYLOAD + ".c")),
        ("surrogate-title", lambda f: f.update(title="\ud800")),
        ("format-title", lambda f: f.update(title="\u202e")),
        ("default-ignorable-title", lambda f: f.update(title="\u034f")),
        ("ad-title", lambda f: f.update(title="\u00ad")),
    ]:
        value = fixtures.confirmed()
        mutate(value)
        add_findings("invalid-confirmed-" + label, [value])

    nv = fixtures.needs_validation()
    nv["severity"] = {"impact": {"score": "low"}, "overall_severity": "low"}
    add_findings("invalid-nv-severity", [nv])
    nv2 = fixtures.needs_validation()
    nv2["blockers"] = []
    add_findings("invalid-nv-blockers", [nv2])
    nv3 = fixtures.needs_validation()
    nv3["validation_plan"] = {}
    add_findings("invalid-nv-plan", [nv3])

    rej = fixtures.rejected()
    rej["fingerprint"] = fixtures.confirmed()["fingerprint"]
    add_findings("invalid-duplicate-fingerprint", [fixtures.confirmed(), rej])
    add_findings("invalid-unsorted", [fixtures.rejected(), fixtures.confirmed()])

    # ---- findings: raw text / structural cases ----
    add_findings_raw("raw-null", "null")
    add_findings_raw("raw-object", "{}")
    add_findings_raw("raw-number", "123")
    add_findings_raw("raw-string", '"hello"')
    add_findings_raw("raw-empty-file", "")
    add_findings_raw("raw-whitespace", "   \n\t ")
    add_findings_raw("raw-syntax-error", "[")
    add_findings_raw("raw-control-syntax-error", "[" + TERMINAL_CONTROL_PAYLOAD + "]")
    add_findings_raw("raw-truncated", '[{"verdict":')
    add_findings_raw("raw-trailing-comma", "[,]")
    add_findings_raw("raw-duplicate-keys", '[{"verdict":"confirmed","verdict":"rejected"}]')
    add_findings_raw("raw-nan", "NaN")
    add_findings_raw("raw-infinity", "Infinity")
    add_findings_raw("raw-number-exponent", "1e3")
    add_findings_raw("raw-deep-nesting-exact", "[" * 64 + "0" + "]" * 64)
    add_findings_raw("raw-deep-nesting-over", "[" * 65 + "0" + "]" * 65)
    add_findings("raw-array-limit-exact", [None] * 1000)
    add_findings("raw-array-limit-over", [None] * 1001)
    add_findings("caps-1000-nulls", [None] * 1000)
    add_findings("many-null-errors", [None] * 1000)

    # 750 amplified findings (near-limit document with capped output).
    amplified = [{
        "verdict": "confirmed",
        "trace": [0] * 1000,
        "evidence": [0] * 1000,
    } for _ in range(750)]
    add_findings("amplified-750", amplified)

    # uniqueItems/canonical-key stress
    add_findings_raw("unique-structured", js_json([{"id": i, "label": str(i)} for i in range(1000)]))

    # undefined-vs-null diagnostics: trace/evidence entries that are not objects
    mixed_trace = fixtures.confirmed()
    mixed_trace["trace"] = [{"verdict": "ok"}, 1, "\ufe0f", []]
    add_findings("trace-with-non-objects", [mixed_trace])
    mixed_trace2 = fixtures.confirmed()
    mixed_trace2["trace"] = [False, "src/a.c"]
    add_findings("trace-with-falsy-non-objects", [mixed_trace2])
    undefined_kind = fixtures.confirmed()
    undefined_kind["trace"] = [{}, fixtures.source("sink")]
    add_findings("trace-missing-kind", [undefined_kind])

    # ledger: unhashable collection members and undefined/null distinctions
    add_ledger("unhashable-status", [dict(fixtures.unit(), status=[{"a": 1}])])
    add_ledger("unhashable-selected-blocks", [fixtures.unit({
        "selected_companion_blocks": ["AI-AND-LLM.md#Tool calls", {"x": 1}, ["y"], 1.5],
        "excluded_blocks": [
            {"block": "AI-AND-LLM.md#Tool calls", "reason": "Claimed irrelevant."},
            {"block": {"x": 1}, "reason": "Non-string block."},
        ],
    })])
    add_ledger("coverage-id-list", [dict(fixtures.unit(), coverage_id=[{}])])
    add_ledger("missing-ordinary-block", [fixtures.unit({"ordinary_attack_class_block": "\u034f"})])
    add_ledger("missing-prior-status", [{
        k: v for k, v in fixtures.unit().items() if k != "prior_status"
    }])
    add_ledger("missing-agent-id", [{
        k: v for k, v in fixtures.unit().items() if k != "agent_id"
    }])
    add_ledger("reviewed-path-ordering", [fixtures.unit({
        "reviewed_paths": ["src/a.c", "ok", "../x", "ok", "src/a.c"],
    })])
    add_ledger("unhashable-prior-owner", [fixtures.unit({
        "status": "in_progress", "agent_id": ["x", "y"],
    })])

    # ---- seeded randomized documents ----
    import random

    rng = random.Random(20241001)
    strings = [
        "", " ", "\t", "\r\n", "caf\u00e9", "\u00ad", "\u034f", "\ufe0f", "\u200b",
        "\u202e", "\u2028", "\u0085", "\ud800", "\udc00", "ok", "src/a.c", "../x",
        "CON", "x" * 300, "\U0001f600", "e\u0301", "\u0000", "\u007f", "\u2066",
    ]
    keys = [
        "verdict", "trace", "evidence", "line", "file", "kind", "title", "fingerprint",
        "status", "agent_id", "wave", "attempts", "coverage_id", "canonical_refs",
        "surface", "boundary", "subsystem", "attack_class", "reviewed_paths",
        "local_checks", "result_fingerprints", "unresolved", "x", "constructor",
        "0", "1", "lifecycle", "extra",
    ]

    def random_node(depth=0):
        choice = rng.random()
        if depth > 5 or choice < 0.42:
            scalar = rng.random()
            if scalar < 0.5:
                return rng.choice(strings)
            if scalar < 0.7:
                return rng.choice([0, 1, -1, 1.5, 100, 1000.0, 0.0])
            if scalar < 0.8:
                return None
            if scalar < 0.9:
                return rng.choice([True, False])
            return rng.choice(strings)
        if choice < 0.72:
            return [random_node(depth + 1) for _ in range(rng.randint(0, 4))]
        return {rng.choice(keys): random_node(depth + 1) for _ in range(rng.randint(0, 5))}

    for _ in range(60):
        add_findings("fuzz-findings", js_json([random_node() for _ in range(rng.randint(0, 3))]))
    for _ in range(60):
        add_ledger("fuzz-ledger", js_json([random_node() for _ in range(rng.randint(0, 3))]))
    for _ in range(40):
        mutated = fixtures.unit()
        for _ in range(rng.randint(1, 3)):
            mutated[rng.choice(list(mutated.keys()))] = random_node(1)
        add_ledger("fuzz-unit", js_json([mutated]))

    # ---- ledger: valid documents ----
    add_ledger("valid-empty", [])
    add_ledger("valid-one", [fixtures.unit()])
    add_ledger("valid-covered", [fixtures.unit({
        "status": "covered", "agent_id": "hunter-1",
        "reviewed_paths": ["src/router.ts"], "local_checks": [fixtures.source_check()],
    })])
    add_ledger("valid-reassigned", [fixtures.unit({
        "attempts": [fixtures.archived_attempt()], "wave": 2,
        "status": "in_progress", "agent_id": "hunter-2",
    })])
    add_ledger("valid-candidate", [fixtures.unit({
        "status": "candidate", "agent_id": "hunter-1", "reviewed_paths": ["src/router.ts"],
        "local_checks": [fixtures.source_check("hunter-1", {"invariant": "Ownership is required.", "result": "No check exists."})],
        "result_fingerprints": ["src-router-missing-owner-check"],
        "unresolved": ["validation_budget_exhausted"],
    })])
    add_ledger("valid-max-multibyte", [fixtures.unit({"canonical_refs": {
        "surface": "\u6f22" * 1024,
        "boundary": "\u00e9" * 1024,
        "subsystem": "packages/api",
        "attack_class": "\u6f22" * 1023 + "\u00e9",
    }})])

    # ---- ledger: invalid documents ----
    add_ledger("invalid-duplicate-id", [fixtures.unit(), fixtures.unit()])
    add_ledger("invalid-unsorted", [fixtures.unit({
        "canonical_refs": dict(fixtures.DEFAULT_REFS, surface="zzz"),
    }), fixtures.unit()])
    add_ledger("invalid-missing-attempts", [dict(fixtures.unit(), attempts=None)])
    add_ledger("invalid-bad-status", [fixtures.unit({"status": "invalid-" + TERMINAL_CONTROL_PAYLOAD, "result_fingerprints": ["x"]})])
    add_ledger("invalid-path", [fixtures.unit({"starting_paths": ["../src/router.ts"]})])
    add_ledger("invalid-agent-id", [fixtures.unit({"status": "in_progress", "agent_id": "Hunter-1"})])
    add_ledger("invalid-blocks", [fixtures.unit({
        "selected_companion_blocks": ["AI-AND-LLM.md#Tool calls"],
        "excluded_blocks": [{"block": "AI-AND-LLM.md#Tool calls", "reason": "Claimed irrelevant."}],
    })])
    add_ledger("invalid-artifact", [fixtures.unit({
        "status": "covered", "agent_id": "hunter-1", "reviewed_paths": ["src/router.ts"],
        "local_checks": [fixtures.local_check("hunter-1", {"artifact": "agents/hunter-2/artifacts/result.txt"})],
    })])
    add_ledger("invalid-prose-ignorable", [fixtures.unit({"surface": "\u034f"})])
    add_ledger("invalid-prose-surrogate", [fixtures.unit({"surface": "\ud800"})])
    add_ledger("invalid-collision", [fixtures.unit(), fixtures.unit({"surface": "Delete-user route"})])

    # ---- ledger: raw text / cardinality ----
    add_ledger_raw("raw-null", "null")
    add_ledger_raw("raw-object", '{"units": []}')
    add_ledger_raw("raw-empty-file", "")
    add_ledger_raw("raw-syntax-error", "[")
    add_ledger_raw("raw-control-syntax-error", "[" + TERMINAL_CONTROL_PAYLOAD + "]")
    add_ledger_raw("raw-unterminated-string", '["unterminated')
    add_ledger_raw("raw-mismatched", '[{"field":1]')
    add_ledger_raw("raw-truncated", "[{\"a\":1")
    add_ledger_raw("raw-nesting-64", "[" * 64 + "0" + "]" * 64)
    add_ledger_raw("raw-nesting-65", "[" * 65 + "0" + "]" * 65)
    add_ledger_raw("raw-nesting-20000", "[" * 20000 + "0" + "]" * 20000)
    add_ledger_raw("raw-mega-nesting", "[" * 200000)
    add_ledger_raw("raw-units-over", "[%snull]" % ("null," * 10000))
    add_ledger_raw("raw-items-over", "[[%snull]]" % ("null," * 1000))
    add_ledger_raw("raw-fields-1001", "[{%s}]" % ",".join('"field%d":null' % i for i in range(1001)))
    add_ledger("units-exactly-10000", [None] * 10000)
    add_ledger("units-10001", [None] * 10001)

    return findings, ledger


def run_pair(cjs, py, target, extra_args=None, timeout=60):
    argv_extra = extra_args or []
    node_cmd = [NODE] + argv_extra + [cjs] + ([target] if target is not None else [])
    py_cmd = [PYTHON] + argv_extra + [py] + ([target] if target is not None else [])
    node = subprocess.run(node_cmd, capture_output=True, timeout=timeout)
    py = subprocess.run(py_cmd, capture_output=True, timeout=timeout)
    return node, py


def diff_text(label, left, right):
    import difflib

    left_lines = left.decode("utf-8", "backslashreplace").splitlines(keepends=True)
    right_lines = right.decode("utf-8", "backslashreplace").splitlines(keepends=True)
    return "".join(difflib.unified_diff(left_lines, right_lines, "node", "python"))


def main():
    if not os.path.exists(NODE):
        print("oracle node not found at %s" % NODE)
        return 1

    findings_cases, ledger_cases = content_cases()
    cases = []
    for name, text in findings_cases:
        cases.append((FINDINGS_CJS, FINDINGS_PY, "findings/" + name, text))
    for name, text in ledger_cases:
        cases.append((LEDGER_CJS, LEDGER_PY, "ledger/" + name, text))

    matched = 0
    mismatches = []
    directory = tempfile.mkdtemp(prefix="differential-")
    try:
        for cjs, py, name, text in cases:
            target = os.path.join(directory, "input.json")
            data = text.encode("utf-8", "surrogatepass") if isinstance(text, str) else text
            with open(target, "wb") as handle:
                handle.write(data)
            node, py_result = run_pair(cjs, py, target)
            if (node.returncode, node.stdout, node.stderr) == (py_result.returncode, py_result.stdout, py_result.stderr):
                matched += 1
            else:
                mismatches.append((name, node, py_result))

        # ---- non-UTF-8 input ----
        for validator_cjs, validator_py, label in [
            (FINDINGS_CJS, FINDINGS_PY, "findings/non-utf8"),
            (LEDGER_CJS, LEDGER_PY, "ledger/non-utf8"),
        ]:
            target = os.path.join(directory, "bad.json")
            with open(target, "wb") as handle:
                handle.write(b'["INVALID_\x80_UTF8"]')
            node, py_result = run_pair(validator_cjs, validator_py, target)
            if (node.returncode, node.stdout, node.stderr) == (py_result.returncode, py_result.stdout, py_result.stderr):
                matched += 1
            else:
                mismatches.append((label, node, py_result))

        # ---- missing file ----
        for validator_cjs, validator_py, label in [
            (FINDINGS_CJS, FINDINGS_PY, "findings/missing-file"),
            (LEDGER_CJS, LEDGER_PY, "ledger/missing-file"),
        ]:
            target = os.path.join(directory, "does-not-exist.json")
            node, py_result = run_pair(validator_cjs, validator_py, target)
            if (node.returncode, node.stdout, node.stderr) == (py_result.returncode, py_result.stdout, py_result.stderr):
                matched += 1
            else:
                mismatches.append((label, node, py_result))

        # ---- directory as input ----
        for validator_cjs, validator_py, label in [
            (FINDINGS_CJS, FINDINGS_PY, "findings/directory"),
            (LEDGER_CJS, LEDGER_PY, "ledger/directory"),
        ]:
            node, py_result = run_pair(validator_cjs, validator_py, directory)
            if (node.returncode, node.stdout, node.stderr) == (py_result.returncode, py_result.stdout, py_result.stderr):
                matched += 1
            else:
                mismatches.append((label, node, py_result))

        # ---- symlink ----
        for validator_cjs, validator_py, label in [
            (FINDINGS_CJS, FINDINGS_PY, "findings/symlink"),
            (LEDGER_CJS, LEDGER_PY, "ledger/symlink"),
        ]:
            target = os.path.join(directory, "target-%s.json" % label.replace("/", "-"))
            link = os.path.join(directory, "link-%s.json" % label.replace("/", "-"))
            with open(target, "wb") as handle:
                handle.write(b"[]")
            if os.path.lexists(link):
                os.remove(link)
            os.symlink(target, link)
            node, py_result = run_pair(validator_cjs, validator_py, link)
            if (node.returncode, node.stdout, node.stderr) == (py_result.returncode, py_result.stdout, py_result.stderr):
                matched += 1
            else:
                mismatches.append((label, node, py_result))

        # ---- FIFO ----
        for validator_cjs, validator_py, label in [
            (FINDINGS_CJS, FINDINGS_PY, "findings/fifo"),
            (LEDGER_CJS, LEDGER_PY, "ledger/fifo"),
        ]:
            target = os.path.join(directory, "fifo-%s" % label.replace("/", "-"))
            if os.path.exists(target):
                os.remove(target)
            os.mkfifo(target)
            node, py_result = run_pair(validator_cjs, validator_py, target)
            if (node.returncode, node.stdout, node.stderr) == (py_result.returncode, py_result.stdout, py_result.stderr):
                matched += 1
            else:
                mismatches.append((label, node, py_result))

        # ---- oversized input (over 5 MiB) ----
        for validator_cjs, validator_py, label in [
            (FINDINGS_CJS, FINDINGS_PY, "findings/oversized"),
            (LEDGER_CJS, LEDGER_PY, "ledger/oversized"),
        ]:
            target = os.path.join(directory, "oversized-%s.json" % label.replace("/", "-"))
            with open(target, "wb") as handle:
                handle.write(b" " * (5 * 1024 * 1024 + 1))
            node, py_result = run_pair(validator_cjs, validator_py, target)
            if (node.returncode, node.stdout, node.stderr) == (py_result.returncode, py_result.stdout, py_result.stderr):
                matched += 1
            else:
                mismatches.append((label, node, py_result))

        # ---- no CLI argument ----
        # The usage line is intentionally runtime-specific ("python3 ..." vs "node ..."),
        # so it is normalized away: exit code, stdout, and the remaining stderr must match.
        for validator_cjs, validator_py, label in [
            (FINDINGS_CJS, FINDINGS_PY, "findings/no-arg"),
            (LEDGER_CJS, LEDGER_PY, "ledger/no-arg"),
        ]:
            node, py_result = run_pair(validator_cjs, validator_py, None)
            node_tail = node.stderr.split(b"\n", 1)[1] if b"\n" in node.stderr else b""
            py_tail = py_result.stderr.split(b"\n", 1)[1] if b"\n" in py_result.stderr else b""
            if (node.returncode, node.stdout, node_tail) == (py_result.returncode, py_result.stdout, py_tail):
                matched += 1
            else:
                mismatches.append((label, node, py_result))
    finally:
        shutil.rmtree(directory, ignore_errors=True)

    total = matched + len(mismatches)
    print("differential: %d/%d cases matched exactly" % (matched, total))
    for name, node, py_result in mismatches:
        print("\n=== MISMATCH: %s" % name)
        print("exit: node=%d python=%d" % (node.returncode, py_result.returncode))
        if node.stdout != py_result.stdout:
            print("--- stdout ---")
            print(diff_text(name, node.stdout, py_result.stdout))
        if node.stderr != py_result.stderr:
            print("--- stderr ---")
            print(diff_text(name, node.stderr, py_result.stderr))
    return 0 if not mismatches else 2


if __name__ == "__main__":
    sys.exit(main())
