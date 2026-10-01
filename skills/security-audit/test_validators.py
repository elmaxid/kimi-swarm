#!/usr/bin/env python3
"""Python translation of the upstream Node conformance suite.

This mirrors validate-findings.test.cjs and validate-coverage-ledger.test.cjs
case for case, exercising both the in-process validators and the CLIs.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import _validate_common as common  # noqa: E402


def _load(name, filename):
    import importlib.util

    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, filename))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


vf = _load("validate_findings", "validate-findings.py")
vcl = _load("validate_coverage_ledger", "validate-coverage-ledger.py")

PYTHON = sys.executable
FINDINGS_CLI = os.path.join(HERE, "validate-findings.py")
LEDGER_CLI = os.path.join(HERE, "validate-coverage-ledger.py")
SCHEMA = json.load(open(os.path.join(HERE, "report-schema.json"), encoding="utf-8"))

CLI_TIMEOUT_MS = 5000
HOSTILE_CLI_TIMEOUT_MS = 15000
HAS_SAFE_INPUT_OPEN = bool(getattr(os, "O_NOFOLLOW", 0)) and bool(getattr(os, "O_NONBLOCK", 0))

TERMINAL_CONTROL_PAYLOAD = "\u001b\u0007\u0085\u202e\u034f\ufe0f"
TERMINAL_CONTROL_BYTES = [
    b"\x1b", b"\x07", "\u0085".encode("utf-8"), "\u202e".encode("utf-8"),
    "\u034f".encode("utf-8"), "\ufe0f".encode("utf-8"),
]
LEDGER_TERMINAL_CONTROL_PAYLOAD = "\u001b\u0007\u0085\u202e"
LEDGER_TERMINAL_CONTROL_BYTES = [
    b"\x1b", b"\x07", "\u0085".encode("utf-8"), "\u202e".encode("utf-8"),
]


def has_lone_surrogate(value):
    return any(0xD800 <= ord(ch) <= 0xDFFF for ch in value)


def write_utf8(path, contents):
    if isinstance(contents, bytes):
        with open(path, "wb") as handle:
            handle.write(contents)
        return
    with open(path, "wb") as handle:
        handle.write(contents.encode("utf-8", "surrogatepass"))


def js_json(value):
    """Serialize a Python value the way the Node tests' JSON.stringify does.

    Lone surrogates are escaped as ``\\uXXXX`` exactly like JSON.stringify, so
    the bytes written to disk are valid UTF-8.
    """
    text = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return re.sub(r"[\ud800-\udfff]", lambda match: "\\u%04x" % ord(match.group()), text)


def run_cli(validator, contents, timeout=CLI_TIMEOUT_MS, extra_args=None):
    directory = tempfile.mkdtemp(prefix="py-validator-")
    target = os.path.join(directory, os.path.basename(validator).replace(".py", ".json"))
    try:
        write_utf8(target, contents)
        args = [PYTHON]
        if extra_args:
            args.extend(extra_args)
        args.extend([validator, target])
        completed = subprocess.run(
            args, capture_output=True, timeout=timeout / 1000.0
        )
        return completed
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def cli_output(result):
    return result.stdout.decode("utf-8", "surrogatepass") + result.stderr.decode("utf-8", "surrogatepass")


def assert_no_injected_control_bytes(testcase, output, markers):
    raw = output if isinstance(output, bytes) else output.encode("utf-8", "surrogatepass")
    for marker in markers:
        testcase.assertEqual(raw.find(marker), -1, "found raw control bytes %s" % marker.hex())


# ---------------------------------------------------------------------------
# Findings fixtures
# ---------------------------------------------------------------------------

def source(kind="entrypoint", file="src/handler.c", line=10):
    return {"kind": kind, "file": file, "line": line, "scope": "handle",
            "description": "Attacker data reaches the operation."}


def evidence(file="src/handler.c", line=10):
    return {"file": file, "line": line,
            "description": "The source performs the operation without the required check."}


def confirmed():
    return {
        "verdict": "confirmed",
        "fingerprint": "src-handler-missing-check",
        "title": "Missing ownership check",
        "description": "An attacker can reach an operation without the intended ownership check.",
        "root_cause": "handle omits the ownership check before changing the object.",
        "intended_behavior": "Only the object's owner can change it.",
        "trace": [source("entrypoint"), source("propagation", "src/model.c", 20), source("sink", "src/store.c", 30)],
        "evidence": [evidence()],
        "conditions": [],
        "execution": {
            "attacker_perspective": "An unprivileged remote user with their own account.",
            "payloads": ["An object identifier owned by another user."],
            "instructions": ["Submit the identifier through the public operation."],
            "observed_result": "The other user's object changes.",
        },
        "remediation": {"strategy": "Check ownership before the state change."},
        "severity": {
            "likelihood": {"score": "medium", "reason": "The operation is directly reachable."},
            "impact": {"score": "medium", "reason": "The attacker changes one protected object."},
            "overall_severity": "medium",
        },
        "confidence": {"score": "high", "reason": "The source path and result were reproduced."},
    }


def needs_validation():
    return {
        "verdict": "needs_validation",
        "fingerprint": "src-parser-size-hypothesis",
        "title": "Unchecked parsed size",
        "description": "A parsed size may reach an allocation without a limit.",
        "claimed_root_cause": "parse_size may pass an unbounded value to allocate.",
        "trace": [source()],
        "evidence": [evidence()],
        "blockers": ["The generated parser source is absent from this checkout."],
        "validation_plan": {
            "local": "Generate the parser and submit the smallest input that exceeds the documented limit.",
            "deployment": "In an approved test deployment, confirm the request reaches the generated parser and record the bounded observable result.",
        },
    }


def rejected():
    return {
        "verdict": "rejected",
        "fingerprint": "src-router-auth-bypass",
        "title": "Authorization bypass in router",
        "description": "The candidate claimed a route bypassed authorization.",
        "claimed_root_cause": "dispatch was claimed to skip the authorization wrapper.",
        "trace": [source("sink")],
        "evidence": [evidence()],
        "reason": "All routes pass through the authorization wrapper before dispatch.",
    }


def errors_for(value):
    return vf.validate_document(value, SCHEMA)


def producer_shaped_findings():
    demonstrated = confirmed()
    demonstrated["conditions"] = [{
        "kind": "authentication_level",
        "description": "The attacker needs a normal account.",
    }]
    demonstrated["execution"]["payloads"] = ["", " \t\r\n", "\u0000\u001f\u007f", "\u034f", "\ufe0f", "\ud800", "\udc00", '[{,}]\\"']
    demonstrated["remediation"]["code_changes"] = [{"file_name": "src/handler.c", "fixed_code": ""}]

    blocked = needs_validation()
    del blocked["validation_plan"]["deployment"]
    return [demonstrated, blocked, rejected()]


def reject_mutation(factory, mutate):
    value = factory()
    mutate(value)
    assert len(errors_for([value])) != 0


class FindingsTests(unittest.TestCase):
    def test_schema_shape(self):
        self.assertEqual(SCHEMA["type"], "array")
        branches = SCHEMA["items"]["oneOf"]
        self.assertEqual(len(branches), 3)
        self.assertEqual([b["properties"]["verdict"]["const"] for b in branches],
                         ["confirmed", "needs_validation", "rejected"])
        confirmed_schema = branches[0]["properties"]
        self.assertEqual(confirmed_schema["title"]["visibleContent"], True)
        self.assertNotIn("minLength", confirmed_schema["execution"]["properties"]["payloads"]["items"])
        self.assertNotIn("visibleContent", confirmed_schema["execution"]["properties"]["payloads"]["items"])
        self.assertNotIn("minLength", confirmed_schema["remediation"]["properties"]["code_changes"]["items"]["properties"]["fixed_code"])

    def test_accepts_producer_shaped_document_through_cli(self):
        result = run_cli(FINDINGS_CLI, js_json(producer_shaped_findings()))
        self.assertEqual(result.returncode, 0, cli_output(result))
        self.assertRegex(result.stdout.decode(), r"PASS: 3 findings valid")

    def test_accepts_empty_output_and_each_complete_branch(self):
        self.assertEqual(list(errors_for([])), [])
        self.assertEqual(list(errors_for([confirmed(), needs_validation(), rejected()])), [])
        local_only = needs_validation()
        del local_only["validation_plan"]["deployment"]
        self.assertEqual(list(errors_for([local_only])), [])
        deployment_only = needs_validation()
        del deployment_only["validation_plan"]["local"]
        self.assertEqual(list(errors_for([deployment_only])), [])

    def test_allows_one_line_trace(self):
        finding = confirmed()
        finding["trace"] = [source("entrypoint")]
        self.assertEqual(list(errors_for([finding])), [])

    def test_rejects_empty_required_content(self):
        cases = [
            (confirmed, lambda f: f.update(title="")),
            (confirmed, lambda f: f.update(title="   ")),
            (confirmed, lambda f: f.update(evidence=[])),
            (confirmed, lambda f: f["execution"].update(payloads=[])),
            (confirmed, lambda f: f["execution"].update(instructions=[])),
            (confirmed, lambda f: f["execution"].update(observed_result="")),
            (confirmed, lambda f: f["remediation"].update(strategy="")),
            (needs_validation, lambda f: f.update(blockers=[])),
            (needs_validation, lambda f: f.update(validation_plan={})),
            (needs_validation, lambda f: f.update(validation_plan={"local": " "})),
            (rejected, lambda f: f.update(claimed_root_cause="")),
        ]
        for factory, mutate in cases:
            reject_mutation(factory, mutate)

    def test_preserves_exact_payload_and_replacements(self):
        finding = confirmed()
        payloads = ["", " \t\r\n", "\u0000\u001f\u007f", "\u034f", "\ufe0f", "\ud800", "\udc00"]
        fixed_code = "\u0000 \t\r\n\u001f\u007f\u034f\ufe0f\ud800x\udc00"
        finding["execution"]["payloads"] = list(payloads)
        finding["remediation"]["code_changes"] = [{"file_name": "src/handler.c", "fixed_code": fixed_code}]
        self.assertEqual(list(errors_for([finding])), [])
        self.assertEqual(finding["execution"]["payloads"], payloads)
        self.assertEqual(finding["remediation"]["code_changes"][0]["fixed_code"], fixed_code)

    def test_rejects_invisible_prose(self):
        for invisible in ["\u0000\t\r\n\u001f\u007f\u200b", "\u034f", "\ufe0f", "\ud800", "\udc00", "visible\ud800"]:
            cases = [
                (confirmed, lambda f, v=invisible: f.update(title=v)),
                (confirmed, lambda f, v=invisible: f["trace"][0].update(scope=v)),
                (confirmed, lambda f, v=invisible: f["evidence"][0].update(description=v)),
                (confirmed, lambda f, v=invisible: f["execution"].update(instructions=[v])),
                (confirmed, lambda f, v=invisible: f["remediation"].update(strategy=v)),
                (confirmed, lambda f, v=invisible: f["severity"]["impact"].update(reason=v)),
                (confirmed, lambda f, v=invisible: f["confidence"].update(reason=v)),
                (needs_validation, lambda f, v=invisible: f.update(blockers=[v])),
                (needs_validation, lambda f, v=invisible: f.update(validation_plan={"local": v})),
                (rejected, lambda f, v=invisible: f.update(reason=v)),
            ]
            for factory, mutate in cases:
                reject_mutation(factory, mutate)

    def test_quotes_input_derived_controls(self):
        finding = confirmed()
        finding["trace"][0]["kind"] = "invalid-" + TERMINAL_CONTROL_PAYLOAD
        finding["execution"]["extra-" + TERMINAL_CONTROL_PAYLOAD] = "value"

        cyclic = {}
        cyclic["path-" + TERMINAL_CONTROL_PAYLOAD] = cyclic
        output = "\n".join(
            list(errors_for([finding])) + list(vf.collect(cyclic, {"type": "object"}, "$input"))
        )
        for escaped in ["\\u001b", "\\u0007", "\\u0085", "\\u202e", "\\u034f", "\\ufe0f"]:
            self.assertIn(escaped, output, "missing escaped diagnostic %s" % escaped)
        assert_no_injected_control_bytes(self, output, TERMINAL_CONTROL_BYTES)

    def test_rejects_line_zero(self):
        reject_mutation(confirmed, lambda f: f["trace"][0].update(line=0))
        reject_mutation(rejected, lambda f: f["evidence"][0].update(line=0))

    def test_does_not_treat_prototype_properties_as_schema_properties(self):
        reject_mutation(confirmed, lambda f: f.update(constructor="not allowed"))
        inherited = {"verdict": "confirmed"}
        self.assertTrue(any("exactly one" in e for e in errors_for([inherited])))
        collected = vf.collect(
            {},
            {"type": "object", "properties": {"constructor": {"type": "string"}},
             "required": ["constructor"], "additionalProperties": False},
        )
        self.assertTrue(any("missing required" in e for e in collected))

    def test_oneof_requires_exactly_one_passing_branch(self):
        self.assertTrue(any("matched 2" in e for e in vf.collect("value", {"oneOf": [{"type": "string"}, {"minLength": 1}]}, "$test")))
        self.assertTrue(any("matched 0" in e for e in vf.collect(7, {"oneOf": [{"type": "string"}, {"minimum": 10}]}, "$test")))

    def test_rejects_duplicate_fingerprints_and_unique_array_entries(self):
        first = confirmed()
        second = rejected()
        second["fingerprint"] = first["fingerprint"]
        self.assertTrue(any("duplicate of" in e for e in errors_for([first, second])))
        reject_mutation(needs_validation, lambda f: f.update(blockers=[f["blockers"][0], f["blockers"][0]]))

    def test_canonical_set_uniqueness_at_array_limit(self):
        entries = [{"id": i, "label": str(i)} for i in range(vf.LIMITS["arrayItems"])]
        self.assertEqual(list(vf.collect(entries, {"type": "array", "uniqueItems": True})), [])
        duplicate = entries[:-1]
        duplicate.append({"label": "0", "id": 0})
        self.assertTrue(any("duplicate at index %d" % (vf.LIMITS["arrayItems"] - 1) in e
                            for e in vf.collect(duplicate, {"type": "array", "uniqueItems": True})))

    def test_bounds_canonical_uniqueness_keys_and_storage(self):
        oversized = "x" * (vf.LIMITS["canonicalKeyBytes"] + 1)
        self.assertTrue(any("canonical key exceeds" in e
                            for e in vf.collect([oversized], {"type": "array", "uniqueItems": True})))
        item_length = vf.LIMITS["uniqueSetBytes"] // 6
        large = ["%d%s" % (index, "x" * item_length) for index in range(6)]
        self.assertTrue(any("canonical uniqueness set exceeds" in e
                            for e in vf.collect(large, {"type": "array", "uniqueItems": True})))

    def test_requires_findings_sorted_by_fingerprint(self):
        first = confirmed()
        second = rejected()
        self.assertTrue(any("sorted lexicographically" in e for e in errors_for([second, first])))

    def test_rejects_severity_above_demonstrated_impact(self):
        def mutate(f):
            f["severity"]["overall_severity"] = "high"
            f["severity"]["impact"]["score"] = "medium"
        reject_mutation(confirmed, mutate)

    def test_rejects_unsafe_source_paths(self):
        bad_paths = [
            "/etc/passwd", "../src/file.c", "src/../file.c", "src//file.c", "C:\\src\\file.c",
            "src/file:name.c", "src/file\nname.c", "src/file\u0001name.c", "src/file\u0085name.c",
            "src/file\u2028name.c", "src/file\u202ename.c", "src/file\u2066name.c", "src/file\u200dname.c",
            "src/file\u034fname.c", "src/file\ufe0fname.c", "src/file\ud800name.c", "src/file\udc00name.c",
            "CON", "src/con.txt", "src/PRN", "src/AUX.c", "src/NUL", "src/COM1.log", "src/lpt9",
            "src/CONIN$", "src/CONOUT$.txt", "src/CLOCK$.txt", "src/COM\u00b9.log", "src/LPT\u00b2.log",
            "src /file.c", "src./file.c", "src/file.c ", "src/file.c.",
        ]
        for bad_path in bad_paths:
            reject_mutation(confirmed, lambda f, p=bad_path: f["trace"][0].update(file=p))
        reject_mutation(rejected, lambda f: f["evidence"][0].update(file="NUL.txt"))
        reject_mutation(confirmed, lambda f: f["remediation"].update(code_changes=[{"file_name": "src/file:name.c", "fixed_code": "replacement"}]))

    def test_accepts_legitimate_unicode_paths_and_prose(self):
        finding = confirmed()
        finding["title"] = "Finding \U0001f600 cafe\u0301"
        finding["trace"][0]["file"] = "src/\u65e5\u672c\u8a9e/cafe\u0301-\U0001f600.ts"
        finding["evidence"][0]["file"] = "src/ma\u00f1ana/\u0444\u0430\u0439\u043b.ts"
        finding["remediation"]["code_changes"] = [{"file_name": "src/\u4fee\u6b63/\u00e9xito.ts", "fixed_code": "replacement"}]
        self.assertEqual(list(errors_for([finding])), [])

    def test_cli_rejects_input_above_byte_limit(self):
        result = run_cli(FINDINGS_CLI, b" " * (vf.LIMITS["inputBytes"] + 1))
        output = cli_output(result)
        self.assertEqual(result.returncode, 1, output)
        self.assertRegex(output, r"input exceeds %d byte limit" % vf.LIMITS["inputBytes"])
        self.assertNotRegex(output, r"RangeError|Maximum call stack|heap out of memory")

    def test_cli_rejects_invalid_utf8(self):
        findings = producer_shaped_findings()
        findings[0]["execution"]["payloads"] = ["INVALID_UTF8"]
        encoded = js_json(findings).encode("utf-8", "surrogatepass")
        marker = b"INVALID_UTF8"
        offset = encoded.find(marker)
        self.assertNotEqual(offset, -1)
        malformed = encoded[:offset] + b"\x80" + encoded[offset + len(marker):]
        result = run_cli(FINDINGS_CLI, malformed)
        output = cli_output(result)
        self.assertEqual(result.returncode, 1, output)
        self.assertRegex(output, r"input is not valid UTF-8")
        self.assertNotRegex(output, r"TypeError|stack|at validate-findings")

    @unittest.skipUnless(HAS_SAFE_INPUT_OPEN, "safe input open unavailable")
    def test_quotes_controls_in_cli_errors(self):
        finding = confirmed()
        finding["trace"][0]["kind"] = "invalid-" + TERMINAL_CONTROL_PAYLOAD
        finding["execution"]["extra-" + TERMINAL_CONTROL_PAYLOAD] = "value"
        result = run_cli(FINDINGS_CLI, js_json([finding]))
        self.assertEqual(result.returncode, 1, cli_output(result))
        self.assertRegex(result.stderr.decode(), r"\$\[0\]\.trace\[0\]\.kind")
        self.assertRegex(result.stderr.decode(), r"\\u001b")
        self.assertRegex(result.stderr.decode(), r"\\u202e")
        assert_no_injected_control_bytes(self, result.stderr, TERMINAL_CONTROL_BYTES)

    @unittest.skipUnless(HAS_SAFE_INPUT_OPEN, "safe input open unavailable")
    def test_generic_syntax_error_without_controls(self):
        malformed = b"[" + TERMINAL_CONTROL_PAYLOAD.encode("utf-8") + b"]"
        result = run_cli(FINDINGS_CLI, malformed)
        self.assertEqual(result.returncode, 1, cli_output(result))
        self.assertEqual(result.stderr.decode(), "Failed to parse findings JSON: invalid JSON syntax\n")
        assert_no_injected_control_bytes(self, result.stderr, TERMINAL_CONTROL_BYTES)

    def test_does_not_reflect_controls_from_failed_path(self):
        directory = tempfile.mkdtemp(prefix="validate-findings-path-")
        missing = os.path.join(directory, "missing-%s.json" % TERMINAL_CONTROL_PAYLOAD)
        try:
            completed = subprocess.run([PYTHON, FINDINGS_CLI, missing], capture_output=True, timeout=5)
            self.assertEqual(completed.returncode, 1, cli_output(completed))
            self.assertRegex(completed.stderr.decode(), r"Failed to read findings JSON:")
            assert_no_injected_control_bytes(self, completed.stderr, TERMINAL_CONTROL_BYTES)
        finally:
            shutil.rmtree(directory, ignore_errors=True)

    def test_cli_rejects_lone_surrogate_prose(self):
        findings = producer_shaped_findings()
        findings[0]["title"] = "\ud800"
        result = run_cli(FINDINGS_CLI, js_json(findings))
        output = cli_output(result)
        self.assertEqual(result.returncode, 1, output)
        self.assertRegex(output, r"must contain only valid Unicode scalar values")
        self.assertNotRegex(output, r"stack|at validate-findings")

    def test_cli_rejects_format_controls_in_source_paths(self):
        findings = producer_shaped_findings()
        findings[0]["trace"][0]["file"] = "src/file\u202ename.c"
        result = run_cli(FINDINGS_CLI, js_json(findings))
        output = cli_output(result)
        self.assertEqual(result.returncode, 1, output)
        self.assertRegex(output, r"must be a safe repository-relative source path")
        self.assertNotRegex(output, r"stack|at validate-findings")

    @unittest.skipUnless(HAS_SAFE_INPUT_OPEN and hasattr(os, "mkfifo"), "fifo unavailable")
    def test_cli_rejects_fifo_without_blocking(self):
        directory = tempfile.mkdtemp(prefix="validate-findings-fifo-")
        fifo = os.path.join(directory, "findings.json")
        try:
            os.mkfifo(fifo)
            completed = subprocess.run([PYTHON, FINDINGS_CLI, fifo], capture_output=True, timeout=5)
            output = cli_output(completed)
            self.assertEqual(completed.returncode, 1, output)
            self.assertRegex(output, r"input must be a regular file")
            self.assertNotRegex(output, r"stack|at validate-findings")
        finally:
            shutil.rmtree(directory, ignore_errors=True)

    @unittest.skipUnless(HAS_SAFE_INPUT_OPEN, "symlink unavailable")
    def test_cli_rejects_symlink(self):
        directory = tempfile.mkdtemp(prefix="validate-findings-symlink-")
        target = os.path.join(directory, "target.json")
        link = os.path.join(directory, "findings.json")
        try:
            write_utf8(target, js_json(producer_shaped_findings()))
            os.symlink(target, link)
            completed = subprocess.run([PYTHON, FINDINGS_CLI, link], capture_output=True, timeout=5)
            output = cli_output(completed)
            self.assertEqual(completed.returncode, 1, output)
            self.assertRegex(output, r"input must not be a symlink")
            self.assertNotRegex(output, r"stack|at validate-findings")
        finally:
            shutil.rmtree(directory, ignore_errors=True)

    def test_cli_rejects_excess_nesting_depth(self):
        levels = vf.LIMITS["nestingDepth"] + 1
        result = run_cli(FINDINGS_CLI, "[" * levels + "0" + "]" * levels)
        output = cli_output(result)
        self.assertEqual(result.returncode, 1, output)
        self.assertRegex(output, r"%d level nesting depth limit" % vf.LIMITS["nestingDepth"])
        self.assertNotRegex(output, r"RangeError|Maximum call stack|heap out of memory")

    def test_cli_rejects_oversized_array(self):
        result = run_cli(FINDINGS_CLI, js_json([None] * (vf.LIMITS["arrayItems"] + 1)))
        output = cli_output(result)
        self.assertEqual(result.returncode, 1, output)
        self.assertRegex(output, r"%d item array limit" % vf.LIMITS["arrayItems"])
        self.assertNotRegex(output, r"RangeError|Maximum call stack|heap out of memory")

    def test_checks_pattern_and_branch_invariants(self):
        reject_mutation(rejected, lambda f: f.update(fingerprint="not stable"))
        reject_mutation(needs_validation, lambda f: f.update(severity={"impact": {"score": "low"}, "overall_severity": "low"}))

    def test_rejects_unsupported_and_malformed_schema_keywords(self):
        self.assertTrue(any("format" in e for e in vf.collect_schema_errors({"type": "string", "format": "uuid"})))
        self.assertTrue(any("regular expression" in e for e in vf.collect_schema_errors({"type": "string", "pattern": "["})))
        self.assertTrue(any("expected boolean" in e for e in vf.collect_schema_errors({"type": "string", "visibleContent": "yes"})))
        self.assertTrue(any("requires type" in e for e in vf.collect_schema_errors({"type": "array", "visibleContent": True})))
        self.assertNotEqual(len(vf.validate_document([], {"type": "array", "maxItems": 1})), 0)

    def test_caps_malformed_findings_output(self):
        self.assertEqual(len(errors_for([None] * vf.LIMITS["arrayItems"])), vf.LIMITS["validationErrors"])
        if not HAS_SAFE_INPUT_OPEN:
            return
        result = run_cli(FINDINGS_CLI, js_json([None] * vf.LIMITS["arrayItems"]))
        output = cli_output(result)
        self.assertEqual(result.returncode, 1, output)
        self.assertRegex(output, r"output capped at 100")
        self.assertLess(len(output), 20000, "unexpected output length %d" % len(output))
        self.assertNotRegex(output, r"RangeError|Maximum call stack|stack|at validate-findings")

    @unittest.skipUnless(HAS_SAFE_INPUT_OPEN, "safe input open unavailable")
    def test_caps_amplified_in_limit_findings_output(self):
        findings = [{
            "verdict": "confirmed",
            "trace": [0] * vf.LIMITS["arrayItems"],
            "evidence": [0] * vf.LIMITS["arrayItems"],
        } for _ in range(750)]
        contents = js_json(findings)
        self.assertGreater(len(contents), 3 * 1000 * 1000)
        self.assertLessEqual(len(contents), vf.LIMITS["inputBytes"])
        result = run_cli(FINDINGS_CLI, contents, timeout=HOSTILE_CLI_TIMEOUT_MS)
        output = cli_output(result)
        self.assertEqual(result.returncode, 1, output)
        self.assertRegex(output, r"output capped at 100")
        self.assertLess(len(output), 20000, "unexpected output length %d" % len(output))
        self.assertNotRegex(output, r"heap out of memory|allocation failed|RangeError|Maximum call stack")

    def test_shared_helpers_aligned(self):
        # The upstream cross-validator test: identical character classes,
        # identical shared LIMITS, and identical path/prose verdicts.
        self.assertEqual(vf.LIMITS["inputBytes"], vcl.LIMITS["inputBytes"])
        self.assertEqual(vf.LIMITS["nestingDepth"], vcl.LIMITS["nestingDepth"])
        self.assertEqual(vf.LIMITS["validationErrors"], vcl.LIMITS["validationErrors"])

        path_corpus = [
            "src/handler.js", "src/caf\u00e9/handler.js", "src/\u65e5\u672c\u8a9e/\u0444\u0430\u0439\u043b.ts",
            "src/cloc\u212a$.txt", "src/CLOCK$.txt", "src/con.txt", "CON", "src/COM\u00b9.log", "src/lpt\u00b3",
            "/etc/passwd", "../src/file.c", "src/../file.c", "src//file.c", "src\\file.c", "src/file:name.c",
            "~home/file.c", "C:/file.c", "src/file.c ", "src/file.c.", "src/file\u202ename.c",
            "src/file\u200b.js", "src/file\u034f.js", "src/file\ufe0f.js", "src/file\ud800name.c", "src/file\udc00name.c",
        ]
        for value in path_corpus:
            self.assertEqual(vf.is_safe_relative_source_path(value), vcl.is_safe_relative_path(value),
                             "path verdict diverges for %r" % value)
        self.assertFalse(vf.is_safe_relative_source_path("src/cloc\u212a$.txt"))
        self.assertFalse(vcl.is_safe_relative_path("src/cloc\u212a$.txt"))

        prose_corpus = ["Valid prose.", "caf\u00e9", "", " \t\r\n", "\u200b", "\u034f", "\ufe0f", "\ud800", "\udc00", "visible\ud800"]
        for value in prose_corpus:
            self.assertEqual(vf.has_visible_prose(value), vcl.has_visible_prose(value),
                             "prose verdict diverges for %r" % value)


# ---------------------------------------------------------------------------
# Coverage-ledger fixtures
# ---------------------------------------------------------------------------

DEFAULT_REFS = {
    "surface": "src/router.ts#POST /users/:id",
    "boundary": "src/authz.ts#requireOwner",
    "subsystem": "packages/api",
    "attack_class": "ATTACK-CLASSES.md#Access control",
}


def unit(overrides=None):
    overrides = overrides or {}
    canonical_refs = overrides.get("canonical_refs") or dict(DEFAULT_REFS)
    value = {
        "coverage_id": vcl.canonical_coverage_id(canonical_refs),
        "canonical_refs": canonical_refs,
        "surface": "Update-user route",
        "boundary": "Object ownership",
        "subsystem": "API",
        "attack_class": "Access control",
        "starting_paths": ["src/router.ts", "src/authz.ts"],
        "ordinary_attack_class_block": "ATTACK-CLASSES.md#Access control",
        "selected_companion_blocks": [],
        "excluded_blocks": [{"block": "WEB-PROTOCOL-AND-AUTH.md#Cache behavior", "reason": "The route is not cached."}],
        "prior_status": "new",
        "attempts": [],
        "wave": 1,
        "status": "planned",
        "agent_id": None,
        "reviewed_paths": [],
        "local_checks": [],
        "result_fingerprints": [],
        "unresolved": [],
    }
    value.update(overrides)
    value["canonical_refs"] = canonical_refs
    return value


def ledger_errors_for(value):
    return vcl.validate_document(value)


def source_check(agent_id="hunter-1", overrides=None):
    value = {
        "agent_id": agent_id,
        "reviewed_paths": ["src/router.ts"],
        "invariant": "The route checks object ownership.",
        "method": "source",
        "result": "The owner check applies before the update.",
        "artifact": None,
    }
    value.update(overrides or {})
    return value


def local_check(agent_id="hunter-1", overrides=None):
    value = source_check(agent_id, {
        "method": "local",
        "result": "The bounded fixture accepted the other owner's object.",
        "artifact": "agents/%s/artifacts/result.txt" % agent_id,
    })
    value.update(overrides or {})
    return value


def archived_attempt(overrides=None):
    value = {
        "wave": 1,
        "status": "blocked",
        "agent_id": "hunter-1",
        "reviewed_paths": ["src/router.ts"],
        "local_checks": [source_check()],
        "result_fingerprints": [],
        "unresolved": ["The deployed policy is unavailable."],
        "reassignment_reason": "The critic found an unchecked parallel path.",
    }
    value.update(overrides or {})
    return value


class LedgerTests(unittest.TestCase):
    def test_accepts_empty_ledger_and_complete_units(self):
        self.assertEqual(list(ledger_errors_for([])), [])
        self.assertEqual(list(ledger_errors_for([unit()])), [])

        missing_attempts = unit()
        del missing_attempts["attempts"]
        self.assertTrue(any("missing required field \"attempts\"" in e for e in ledger_errors_for([missing_attempts])))

        covered = unit({"status": "covered", "agent_id": "hunter-1",
                        "reviewed_paths": ["src/router.ts"], "local_checks": [source_check()]})
        self.assertEqual(list(ledger_errors_for([covered])), [])

    @unittest.skipUnless(HAS_SAFE_INPUT_OPEN, "safe input open unavailable")
    def test_accepts_complete_ledger_through_cli(self):
        result = run_cli(LEDGER_CLI, js_json([unit()]))
        self.assertEqual(result.returncode, 0, cli_output(result))
        self.assertRegex(result.stdout.decode(), r"PASS: 1 coverage units valid")

    def test_text_preflight_ignores_structural_characters_in_strings(self):
        value = unit({
            "surface": "Route \\ slash [list] {object}, colon: quoted \"value\"",
            "excluded_blocks": [{
                "block": "COMPANION.md#Literal [brackets] {braces}",
                "reason": "The text contains a backslash \\ before an escaped \"quote\".",
            }],
        })
        contents = js_json([value])
        vcl.preflight_json_text(contents)
        self.assertEqual(json.loads(contents), [value])
        if HAS_SAFE_INPUT_OPEN:
            result = run_cli(LEDGER_CLI, contents)
            self.assertEqual(result.returncode, 0, cli_output(result))

    def test_text_preflight_enforces_structural_limits(self):
        depth_limit = vcl.LIMITS["nestingDepth"]
        vcl.preflight_json_text("[" * depth_limit + "0" + "]" * depth_limit)
        with self.assertRaisesRegex(vcl.JsonStructureError, r"exceeds nesting depth limit 64"):
            vcl.preflight_json_text("[" * (depth_limit + 1) + "0" + "]" * (depth_limit + 1))

        with self.assertRaisesRegex(vcl.JsonStructureError, r"exceeds 10000 top-level unit limit"):
            vcl.preflight_json_text("[%snull]" % ("null," * vcl.LIMITS["units"]))
        with self.assertRaisesRegex(vcl.JsonStructureError, r"exceeds 1000 item array limit"):
            vcl.preflight_json_text("[[%snull]]" % ("null," * vcl.LIMITS["collectionItems"]))

        object_fields = ",".join('"field%d":null' % index for index in range(vcl.LIMITS["objectFields"] + 1))
        with self.assertRaisesRegex(vcl.JsonStructureError, r"exceeds 1000 field object limit"):
            vcl.preflight_json_text("[{%s}]" % object_fields)

        full_array = "[%snull]" % ("null," * (vcl.LIMITS["collectionItems"] - 1))
        arrays_needed = vcl.LIMITS["preflightValues"] // (vcl.LIMITS["collectionItems"] + 1) + 1
        too_many_values = "[%s]" % ",".join(full_array for _ in range(arrays_needed))
        with self.assertRaisesRegex(vcl.JsonStructureError, r"exceeds 500000 total value limit"):
            vcl.preflight_json_text(too_many_values)

    def test_text_preflight_rejects_malformed_truncation(self):
        with self.assertRaisesRegex(vcl.JsonStructureError, r"truncated JSON structure"):
            vcl.preflight_json_text("[")
        with self.assertRaisesRegex(vcl.JsonStructureError, r"unterminated JSON string"):
            vcl.preflight_json_text('["unterminated')
        with self.assertRaisesRegex(vcl.JsonStructureError, r"mismatched JSON containers"):
            vcl.preflight_json_text('[{"field":1]')

    def test_derives_collision_free_canonical_ids(self):
        self.assertEqual(vcl.encode_canonical_ref("route:POST /users"), "route%3APOST%20%2Fusers")
        self.assertNotEqual(vcl.encode_canonical_ref("route name"), vcl.encode_canonical_ref("route-name"))
        self.assertEqual(
            vcl.canonical_coverage_id({"surface": "a", "boundary": "b", "subsystem": "c", "attack_class": "d", "lifecycle": "retry"}),
            "a::b::c::d::retry",
        )
        for bad in ["e\u0301", "bad\u0000ref", "hidden\u200bref"]:
            with self.assertRaisesRegex(TypeError, r"invalid canonical reference"):
                vcl.encode_canonical_ref(bad)

    def test_rejects_noncanonical_duplicate_and_colliding_ids(self):
        wrong = unit({"coverage_id": "display-label-slug"})
        self.assertTrue(any("expected canonical ID" in e for e in ledger_errors_for([wrong])))
        self.assertTrue(any("duplicate coverage ID" in e for e in ledger_errors_for([unit(), unit()])))
        collision = unit()
        different = unit({"surface": "Delete-user route"})
        self.assertTrue(any("canonical identity collision" in e for e in ledger_errors_for([collision, different])))

    def test_requires_canonical_references_to_be_own_properties(self):
        # Python has no prototype chain, so an object missing its own fields is
        # modelled directly by an empty dict.
        value = unit()
        value["canonical_refs"] = {}
        self.assertTrue(any("missing required field" in e for e in ledger_errors_for([value])))

    def test_rejects_aliases_for_one_semantic_tuple(self):
        first = unit()
        refs = dict(first["canonical_refs"])
        refs["surface"] = "src/alias.ts#updateUser"
        alias = unit({"canonical_refs": refs})
        ledger = sorted([first, alias], key=lambda unit_value: unit_value["coverage_id"])
        self.assertTrue(any("semantic tuple already uses coverage ID" in e for e in ledger_errors_for(ledger)))

    def test_requires_lexicographic_order(self):
        second_refs = dict(DEFAULT_REFS)
        second_refs["surface"] = "zzz"
        self.assertTrue(any("sorted lexicographically" in e
                            for e in ledger_errors_for([unit({"canonical_refs": second_refs}), unit()])))

    def test_validates_assignment_block_maps(self):
        overlap = unit({
            "selected_companion_blocks": ["AI-AND-LLM.md#Tool calls"],
            "excluded_blocks": [{"block": "AI-AND-LLM.md#Tool calls", "reason": "Claimed irrelevant."}],
        })
        self.assertTrue(any("also selected" in e for e in ledger_errors_for([overlap])))
        no_reason = unit({"excluded_blocks": [{"block": "AI-AND-LLM.md#Tool calls", "reason": ""}]})
        self.assertTrue(any("reason" in e for e in ledger_errors_for([no_reason])))

    def test_requires_owned_artifacts_and_null_source_artifacts(self):
        local = unit({"status": "covered", "agent_id": "hunter-1",
                      "reviewed_paths": ["src/router.ts"], "local_checks": [local_check()]})
        self.assertEqual(list(ledger_errors_for([local])), [])

        independently = unit({
            "status": "covered", "agent_id": "hunter-1",
            "reviewed_paths": ["src/router.ts", "src/authz.ts"],
            "local_checks": [source_check(), local_check("verifier-1", {"reviewed_paths": ["src/authz.ts"]})],
        })
        self.assertEqual(list(ledger_errors_for([independently])), [])

        unowned = unit({"status": "covered", "agent_id": "hunter-1",
                        "reviewed_paths": ["src/router.ts", "src/authz.ts"], "local_checks": [source_check()]})
        self.assertTrue(any("has no check owner" in e for e in ledger_errors_for([unowned])))

        for check_agent_id, artifact in [
            (None, "agents/hunter-1/artifacts/result.txt"),
            ("hunter-1", None),
            ("hunter-1", "result.txt"),
            ("hunter-1", "agents/hunter-2/artifacts/result.txt"),
            ("../hunter", "agents/../hunter/artifacts/result.txt"),
        ]:
            value = unit({"status": "covered", "agent_id": "hunter-1", "reviewed_paths": ["src/router.ts"],
                          "local_checks": [local_check(check_agent_id, {"artifact": artifact})]})
            self.assertNotEqual(len(ledger_errors_for([value])), 0, "%s: %s" % (check_agent_id, artifact))

        unowned_source = unit({"status": "blocked", "reviewed_paths": ["src/router.ts"],
                               "local_checks": [source_check()],
                               "unresolved": ["The boundary behavior is not source-visible."]})
        self.assertTrue(any('unit with status "blocked" requires a canonical lowercase agent ID' in e
                            for e in ledger_errors_for([unowned_source])))

        source_with_artifact = unit({
            "status": "covered", "agent_id": "hunter-1", "reviewed_paths": ["src/router.ts"],
            "local_checks": [source_check("hunter-1", {"artifact": "agents/hunter-1/artifacts/source.txt"})],
        })
        self.assertTrue(any("source-only check must use null" in e for e in ledger_errors_for([source_with_artifact])))

    def test_requires_canonical_lowercase_agent_ids(self):
        for value in ["hunter-1", "verifier_2", "a0"]:
            self.assertTrue(vcl.is_safe_agent_id(value), value)
        for value in ["Hunter-1", "hunter.1", "hunter-1.", "hunter ", "con", "prn", "aux", "nul", "com1", "lpt9", "../hunter"]:
            self.assertFalse(vcl.is_safe_agent_id(value), value)
        case_alias = unit({"status": "in_progress", "agent_id": "Hunter-1"})
        self.assertTrue(any("canonical lowercase agent ID" in e for e in ledger_errors_for([case_alias])))

    def test_enforces_state_evidence(self):
        self.assertTrue(any('unit with status "in_progress" requires' in e for e in ledger_errors_for([unit({"status": "in_progress"})])))
        self.assertTrue(any("unresolved" in e for e in ledger_errors_for([unit({"status": "blocked"})])))
        self.assertTrue(any("reviewed_paths" in e for e in ledger_errors_for([unit({"status": "candidate"})])))

        self.assertEqual(list(ledger_errors_for([unit({"status": "in_progress", "agent_id": "hunter-1"})])), [])
        in_progress_evidence = unit({"status": "in_progress", "agent_id": "hunter-1",
                                     "reviewed_paths": ["src/router.ts"], "local_checks": [source_check()]})
        self.assertTrue(any("must keep this array empty" in e for e in ledger_errors_for([in_progress_evidence])))

        assigned_planned = unit({"agent_id": "hunter-1", "reviewed_paths": ["src/router.ts"], "local_checks": [source_check()]})
        self.assertTrue(any("planned unit must be unassigned" in e for e in ledger_errors_for([assigned_planned])))

        candidate = unit({
            "status": "candidate", "agent_id": "hunter-1", "reviewed_paths": ["src/router.ts"],
            "local_checks": [source_check("hunter-1", {"invariant": "Ownership is required.", "result": "No check exists."})],
            "result_fingerprints": ["src-router-missing-owner-check"],
            "unresolved": ["validation_budget_exhausted"],
        })
        self.assertEqual(list(ledger_errors_for([candidate])), [])

        blocked = unit({"status": "blocked", "agent_id": "hunter-1", "reviewed_paths": ["src/router.ts"],
                        "local_checks": [source_check()], "unresolved": ["The deployed policy is unavailable."]})
        self.assertEqual(list(ledger_errors_for([blocked])), [])
        blocked_fingerprint = dict(blocked, result_fingerprints=["forbidden-fingerprint"])
        self.assertTrue(any("result_fingerprints" in e for e in ledger_errors_for([blocked_fingerprint])))

        for status in ["not_applicable", "out_of_scope", "deferred"]:
            self.assertEqual(list(ledger_errors_for([unit({"status": status, "unresolved": ["Reason recorded."]})])), [])
            invalid = unit({
                "status": status, "agent_id": "hunter-1", "reviewed_paths": ["src/router.ts"],
                "local_checks": [source_check()], "result_fingerprints": ["forbidden-fingerprint"],
                "unresolved": ["Reason recorded."],
            })
            errors = ledger_errors_for([invalid])
            self.assertTrue(any("must be unassigned" in e for e in errors), status)
            self.assertTrue(any("reviewed_paths" in e for e in errors), status)
            self.assertTrue(any("result_fingerprints" in e for e in errors), status)

        covered_fingerprint = unit({"status": "covered", "agent_id": "hunter-1", "reviewed_paths": ["src/router.ts"],
                                    "local_checks": [source_check()], "result_fingerprints": ["forbidden-fingerprint"]})
        self.assertTrue(any("result_fingerprints" in e for e in ledger_errors_for([covered_fingerprint])))

        covered_unresolved = unit({"status": "covered", "agent_id": "hunter-1", "reviewed_paths": ["src/router.ts"],
                                   "local_checks": [source_check()], "unresolved": ["Unexpected unresolved claim."]})
        self.assertTrue(any("unresolved" in e for e in ledger_errors_for([covered_unresolved])))

    def test_archives_prior_evidence_on_fresh_owner(self):
        reassigned = unit({"attempts": [archived_attempt()], "wave": 2, "status": "in_progress", "agent_id": "hunter-2"})
        self.assertEqual(list(ledger_errors_for([reassigned])), [])

        final_closure = unit({
            "attempts": [archived_attempt()], "wave": 2, "status": "covered", "agent_id": "hunter-2",
            "reviewed_paths": ["src/authz.ts"],
            "local_checks": [source_check("hunter-2", {"reviewed_paths": ["src/authz.ts"]})],
        })
        self.assertEqual(list(ledger_errors_for([final_closure])), [])

    def test_preserves_candidate_provenance_on_deferred(self):
        candidate_attempt = archived_attempt({
            "status": "candidate",
            "result_fingerprints": ["src-router-missing-owner-check"],
            "unresolved": ["validation_budget_exhausted"],
        })
        deferred = unit({"attempts": [candidate_attempt], "wave": 2, "status": "deferred", "unresolved": ["quick_profile_final_critic"]})
        self.assertEqual(list(ledger_errors_for([deferred])), [])

    def test_rejects_reassignment_owner_reuse_and_evidence_mixing(self):
        reused = unit({"attempts": [archived_attempt()], "wave": 2, "status": "in_progress", "agent_id": "hunter-1"})
        self.assertTrue(any("current assignment owner must be fresh" in e for e in ledger_errors_for([reused])))

        mixed = unit({
            "attempts": [archived_attempt({"local_checks": [local_check()]})], "wave": 2, "status": "covered",
            "agent_id": "hunter-2", "reviewed_paths": ["src/router.ts"], "local_checks": [local_check()],
        })
        errors = ledger_errors_for([mixed])
        self.assertTrue(any("prior assignment owner evidence must remain" in e for e in errors))
        self.assertTrue(any("artifact from an archived attempt cannot be reused" in e for e in errors))

        mixed_history = unit({
            "attempts": [
                archived_attempt({"local_checks": [local_check()]}),
                archived_attempt({"wave": 2, "agent_id": "hunter-2", "local_checks": [local_check()]}),
            ],
            "wave": 3, "status": "in_progress", "agent_id": "hunter-3",
        })
        history_errors = ledger_errors_for([mixed_history])
        self.assertTrue(any("prior assignment owner evidence must remain in its earlier attempt" in e for e in history_errors))
        self.assertTrue(any("artifact from an earlier attempt cannot be reused" in e for e in history_errors))

        unordered = unit({
            "attempts": [archived_attempt(), archived_attempt({"wave": 1, "agent_id": "hunter-2", "local_checks": [source_check("hunter-2")]})],
            "wave": 3, "status": "in_progress", "agent_id": "hunter-3",
        })
        self.assertTrue(any("strictly increasing" in e for e in ledger_errors_for([unordered])))

    def test_rejects_unsafe_paths_and_malformed_fingerprints(self):
        for value in [
            "/etc/passwd", "../src/file.js", "src/../file.js", "src/con.txt", "src/PRN", "src/AUX.c", "src/NUL",
            "src/CLOCK$.txt", "src/conin$.txt", "src/conout$", "src/COM1.log", "src/lpt9", "src/COM\u00b9.log",
            "src/COM\u00b2.log", "src/COM\u00b3.log", "src/lpt\u00b9", "src/lpt\u00b2", "src/lpt\u00b3",
            "src/file.js.", "C:/src/file.js", "src/file\n.js", "src/file\u0085.js", "src/file\u2028.js",
            "src/file\u200b.js", "src/file\u034f.js", "src/file\ufe0f.js",
        ]:
            self.assertFalse(vcl.is_safe_relative_path(value), value)
        self.assertTrue(vcl.is_safe_relative_path("src/handler.js"))
        self.assertTrue(vcl.is_safe_relative_path("src/caf\u00e9/handler.js"))
        self.assertTrue(any("repository-relative path" in e for e in ledger_errors_for([unit({"starting_paths": ["../src/router.ts"]})])))
        self.assertTrue(any("invalid fingerprint" in e for e in ledger_errors_for([unit({
            "status": "candidate", "agent_id": "hunter-1", "reviewed_paths": ["src/router.ts"],
            "local_checks": [source_check("hunter-1", {"invariant": "Ownership is required.", "result": "No check exists."})],
            "result_fingerprints": ["not stable"],
        })])))

    def test_rejects_format_default_ignorable_and_invalid_scalar_prose(self):
        for invisible in ["\u200b", "\u034f", "\ufe0f", "\ud800"]:
            self.assertTrue(any("surface" in e for e in ledger_errors_for([unit({"surface": invisible})])), repr(invisible))
            self.assertTrue(any("reason" in e for e in ledger_errors_for([unit({
                "excluded_blocks": [{"block": "ATTACK-CLASSES.md#Access control", "reason": invisible}],
            })])))

    def test_quotes_input_derived_controls_direct(self):
        invalid_status = "invalid-" + LEDGER_TERMINAL_CONTROL_PAYLOAD
        invalid_path = "src/%s.js" % LEDGER_TERMINAL_CONTROL_PAYLOAD
        value = unit({"status": invalid_status, "agent_id": "hunter-1", "reviewed_paths": [invalid_path],
                      "local_checks": [source_check()], "result_fingerprints": ["force-state-error"]})
        output = "\n".join(ledger_errors_for([value]))
        self.assertRegex(output, r"\$\[0\]\.status")
        self.assertRegex(output, r"\$\[0\]\.reviewed_paths")
        self.assertRegex(output, r"\\u001b")
        self.assertRegex(output, r"\\u0007")
        self.assertRegex(output, r"\\u0085")
        self.assertRegex(output, r"\\u202e")
        assert_no_injected_control_bytes(self, output, LEDGER_TERMINAL_CONTROL_BYTES)

    @unittest.skipUnless(HAS_SAFE_INPUT_OPEN, "safe input open unavailable")
    def test_quotes_input_derived_controls_cli(self):
        value = unit({"status": "invalid-" + LEDGER_TERMINAL_CONTROL_PAYLOAD, "result_fingerprints": ["force-state-error"]})
        result = run_cli(LEDGER_CLI, js_json([value]))
        self.assertEqual(result.returncode, 1, cli_output(result))
        self.assertRegex(result.stderr.decode(), r"\$\[0\]\.status")
        self.assertRegex(result.stderr.decode(), r"\\u001b")
        assert_no_injected_control_bytes(self, result.stderr, LEDGER_TERMINAL_CONTROL_BYTES)

    @unittest.skipUnless(HAS_SAFE_INPUT_OPEN, "safe input open unavailable")
    def test_returns_generic_syntax_error(self):
        malformed = b"[" + LEDGER_TERMINAL_CONTROL_PAYLOAD.encode("utf-8") + b"]"
        result = run_cli(LEDGER_CLI, malformed)
        self.assertEqual(result.returncode, 1, cli_output(result))
        self.assertEqual(result.stderr.decode(), "Failed to parse coverage ledger: invalid JSON syntax\n")
        assert_no_injected_control_bytes(self, result.stderr, LEDGER_TERMINAL_CONTROL_BYTES)

    def test_does_not_reflect_controls_from_failed_path(self):
        directory = tempfile.mkdtemp(prefix="validate-coverage-ledger-path-")
        missing = os.path.join(directory, "missing-%s.json" % LEDGER_TERMINAL_CONTROL_PAYLOAD)
        try:
            completed = subprocess.run([PYTHON, LEDGER_CLI, missing], capture_output=True, timeout=5)
            self.assertEqual(completed.returncode, 1, cli_output(completed))
            self.assertRegex(completed.stderr.decode(), r"Failed to read coverage ledger:")
            assert_no_injected_control_bytes(self, completed.stderr, LEDGER_TERMINAL_CONTROL_BYTES)
        finally:
            shutil.rmtree(directory, ignore_errors=True)

    @unittest.skipUnless(HAS_SAFE_INPUT_OPEN, "safe input open unavailable")
    def test_rejects_invalid_utf8_through_cli(self):
        encoded = js_json([unit()]).encode("utf-8", "surrogatepass")
        marker = "Update-user route".encode("utf-8")
        offset = encoded.find(marker)
        self.assertNotEqual(offset, -1)
        malformed = encoded[:offset] + b"\x80" + encoded[offset + len(marker):]
        result = run_cli(LEDGER_CLI, malformed)
        output = cli_output(result)
        self.assertEqual(result.returncode, 1, output)
        self.assertRegex(output, r"input is not valid UTF-8")
        self.assertNotRegex(output, r"TypeError|stack|at validate-coverage-ledger")

    @unittest.skipUnless(HAS_SAFE_INPUT_OPEN and hasattr(os, "mkfifo"), "fifo unavailable")
    def test_rejects_fifo_through_cli(self):
        directory = tempfile.mkdtemp(prefix="validate-coverage-ledger-fifo-")
        fifo = os.path.join(directory, "coverage-ledger.json")
        try:
            os.mkfifo(fifo)
            completed = subprocess.run([PYTHON, LEDGER_CLI, fifo], capture_output=True, timeout=5)
            output = cli_output(completed)
            self.assertEqual(completed.returncode, 1, output)
            self.assertRegex(output, r"input must be a regular file")
            self.assertNotRegex(output, r"stack|at validate-coverage-ledger")
        finally:
            shutil.rmtree(directory, ignore_errors=True)

    @unittest.skipUnless(HAS_SAFE_INPUT_OPEN, "symlink unavailable")
    def test_rejects_symlink_through_cli(self):
        directory = tempfile.mkdtemp(prefix="validate-coverage-ledger-symlink-")
        target = os.path.join(directory, "target.json")
        link = os.path.join(directory, "coverage-ledger.json")
        try:
            write_utf8(target, js_json([unit()]))
            os.symlink(target, link)
            completed = subprocess.run([PYTHON, LEDGER_CLI, link], capture_output=True, timeout=5)
            output = cli_output(completed)
            self.assertEqual(completed.returncode, 1, output)
            self.assertRegex(output, r"input must not be a symlink")
            self.assertNotRegex(output, r"stack|at validate-coverage-ledger")
        finally:
            shutil.rmtree(directory, ignore_errors=True)

    def test_rejects_deeply_nested_input_without_recursion_failure(self):
        nested = 0
        for _ in range(20000):
            nested = [nested]
        self.assertTrue(any("exceeds nesting depth limit 64" in e for e in ledger_errors_for(nested)))
        if not HAS_SAFE_INPUT_OPEN:
            return
        result = run_cli(LEDGER_CLI, "[" * 20000 + "0" + "]" * 20000)
        output = cli_output(result)
        self.assertEqual(result.returncode, 1, output)
        self.assertRegex(output, r"exceeds nesting depth limit 64")
        self.assertNotRegex(output, r"RangeError|Maximum call stack|stack|at validate-coverage-ledger")

    @unittest.skipUnless(HAS_SAFE_INPUT_OPEN, "safe input open unavailable")
    def test_rejects_multi_megabyte_nesting(self):
        open_containers = "[" * 2000000
        for contents in [open_containers, open_containers + "0" + "]" * 2000000]:
            result = run_cli(LEDGER_CLI, contents, timeout=HOSTILE_CLI_TIMEOUT_MS)
            output = cli_output(result)
            self.assertEqual(result.returncode, 1, output)
            self.assertRegex(output, r"exceeds nesting depth limit 64")
            self.assertNotRegex(output, r"heap out of memory|allocation failed|RangeError|Maximum call stack|stack|at validate-coverage-ledger")

    def test_caps_malformed_units_output(self):
        self.assertEqual(len(ledger_errors_for([None] * vcl.LIMITS["units"])), vcl.LIMITS["validationErrors"])
        if not HAS_SAFE_INPUT_OPEN:
            return
        result = run_cli(LEDGER_CLI, js_json([None] * vcl.LIMITS["units"]))
        output = cli_output(result)
        self.assertEqual(result.returncode, 1, output)
        self.assertRegex(output, r"output capped at 100")
        self.assertLess(len(output), 20000, "unexpected output length %d" % len(output))
        self.assertNotRegex(output, r"RangeError|Maximum call stack|stack|at validate-coverage-ledger")

    def test_rejects_malformed_top_level_and_excessive_units(self):
        self.assertEqual(list(ledger_errors_for({"units": []})), ["$: expected a top-level array"])
        too_many = [None] * 10001
        self.assertEqual(list(ledger_errors_for(too_many)), ["$: exceeds 10000 coverage units"])
        oversized = unit({"extra": [None] * (vcl.LIMITS["collectionItems"] + 1)})
        self.assertTrue(any("exceeds 1000 entries" in e for e in ledger_errors_for([oversized])))

    def test_accepts_canonical_id_from_near_max_multibyte_refs(self):
        canonical_refs = {
            "surface": "\u6f22" * 1024,
            "boundary": "\u00e9" * 1024,
            "subsystem": "packages/api",
            "attack_class": "\u6f22" * 1023 + "\u00e9",
        }
        value = unit({"canonical_refs": canonical_refs})
        self.assertGreater(len(value["coverage_id"]), 16384)
        self.assertLessEqual(len(value["coverage_id"]), 65536)
        self.assertEqual(list(ledger_errors_for([value])), [])
        if HAS_SAFE_INPUT_OPEN:
            result = run_cli(LEDGER_CLI, js_json([value]))
            self.assertEqual(result.returncode, 0, cli_output(result))


if __name__ == "__main__":
    unittest.main(verbosity=2)
