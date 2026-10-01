#!/usr/bin/env python3
"""Validates findings.json against report-schema.json.

Usage: python3 validate-findings.py <path-to-findings.json>

Dependency-free Python 3 port of validate-findings.cjs: an interpreter for the
JSON Schema keywords used by report-schema.json plus finding-specific checks.
"""

import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _validate_common import (  # noqa: E402
    SafeInputError,
    code_point_length,
    create_error_list,
    deep_equal,
    escape_unsafe_diagnostic_characters,
    has_valid_unicode_scalar_values,
    get_prop,
    js_truthy,
    set_has,
    has_visible_prose,
    is_finite_number,
    is_js_whitespace,
    is_number,
    is_safe_relative_path,
    js_json_stringify,
    js_number_to_string,
    js_object_keys,
    load_json_text,
    number_is_integer,
    property_path,
    read_file_within_limit,
    safe_quote,
    type_of,
    visible_content_match,
)

SUPPORTED_TYPES = frozenset(["object", "array", "string", "integer", "number", "boolean", "null"])
SUPPORTED_KEYWORDS = frozenset([
    "$comment",
    "additionalProperties",
    "const",
    "description",
    "enum",
    "items",
    "minimum",
    "minItems",
    "minLength",
    "oneOf",
    "pattern",
    "properties",
    "required",
    "type",
    "uniqueItems",
    "visibleContent",
])
SEVERITY_RANK = {
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}
LIMITS = {
    "inputBytes": 5 * 1024 * 1024,
    "nestingDepth": 64,
    "arrayItems": 1000,
    "canonicalKeyBytes": 1024 * 1024,
    "uniqueSetBytes": 5 * 1024 * 1024,
    "validationErrors": 100,
}

VALIDATION_ERRORS = LIMITS["validationErrors"]


class JsonStructureError(Exception):
    pass


def _is_container(value):
    return isinstance(value, (dict, list))


def truthy_trace(entry):
    return js_truthy(entry)


def _utf16_sort_key(value):
    return value.encode("utf-16-be", "surrogatepass")


def canonical_key(value):
    chunks = []
    state = {"bytes": 0}

    def append(chunk):
        state["bytes"] += len(chunk.encode("utf-8"))
        if state["bytes"] > LIMITS["canonicalKeyBytes"]:
            raise ValueError("canonical key exceeds %d byte limit" % LIMITS["canonicalKeyBytes"])
        chunks.append(chunk)

    def encode(item):
        kind = type_of(item)
        if kind == "null":
            append("null")
        elif kind == "string":
            append("string:" + js_json_stringify(item))
        elif kind == "number":
            append("number:" + js_number_to_string(item))
        elif kind == "boolean":
            append("boolean:" + ("true" if item else "false"))
        elif kind == "array":
            append("array:[")
            for index, entry in enumerate(item):
                if index > 0:
                    append(",")
                encode(entry)
            append("]")
        elif kind == "object":
            append("object:{")
            for index, key in enumerate(sorted(js_object_keys(item), key=_utf16_sort_key)):
                if index > 0:
                    append(",")
                append(js_json_stringify(key))
                append(":")
                encode(item[key])
            append("}")
        else:
            append(kind + ":" + js_number_to_string(item))

    encode(value)
    return {"key": "".join(chunks), "bytes": state["bytes"]}


def collect_data_limit_errors(value, location="$data"):
    stack = [(value, location, 1 if _is_container(value) else 0)]
    seen = set()

    while stack:
        current, current_location, depth = stack.pop()
        if not _is_container(current):
            continue
        if depth > LIMITS["nestingDepth"]:
            return [escape_unsafe_diagnostic_characters(
                "%s: exceeds %d level nesting depth limit" % (current_location, LIMITS["nestingDepth"])
            )]
        if id(current) in seen:
            return [escape_unsafe_diagnostic_characters(
                "%s: input must not contain repeated or cyclic object references" % current_location
            )]
        seen.add(id(current))

        if isinstance(current, list):
            if len(current) > LIMITS["arrayItems"]:
                return [escape_unsafe_diagnostic_characters(
                    "%s: exceeds %d item array limit" % (current_location, LIMITS["arrayItems"])
                )]
            for index in range(len(current) - 1, -1, -1):
                child = current[index]
                if _is_container(child):
                    stack.append((child, "%s[%d]" % (current_location, index), depth + 1))
        else:
            keys = js_object_keys(current)
            for index in range(len(keys) - 1, -1, -1):
                key = keys[index]
                child = current[key]
                if _is_container(child):
                    stack.append((child, property_path(current_location, key), depth + 1))

    return []


def collect_schema_errors(schema, location="schema"):
    errors = create_error_list(VALIDATION_ERRORS)

    def check(node, p):
        if not isinstance(node, dict):
            errors.push("%s: schema must be an object" % p)
            return

        for key in js_object_keys(node):
            if key not in SUPPORTED_KEYWORDS:
                errors.push("%s: unsupported schema keyword %s" % (p, safe_quote(key)))

        if "$comment" in node and not isinstance(node["$comment"], str):
            errors.push("%s.$comment: expected string" % p)
        if "description" in node and not isinstance(node["description"], str):
            errors.push("%s.description: expected string" % p)
        if "type" in node and not set_has(SUPPORTED_TYPES, node["type"]):
            errors.push("%s.type: unsupported type %s" % (p, safe_quote(node["type"])))
        if "properties" in node:
            if not isinstance(node["properties"], dict):
                errors.push("%s.properties: expected object" % p)
            else:
                for key in js_object_keys(node["properties"]):
                    check(node["properties"][key], property_path(p + ".properties", key))
        if "required" in node:
            required = node["required"]
            if not isinstance(required, list) or any(not isinstance(key, str) for key in required):
                errors.push("%s.required: expected an array of strings" % p)
            elif len(set(required)) != len(required):
                errors.push("%s.required: entries must be unique" % p)
        if "additionalProperties" in node and not isinstance(node["additionalProperties"], bool):
            errors.push("%s.additionalProperties: only boolean values are supported" % p)
        if "enum" in node:
            enum = node["enum"]
            if not isinstance(enum, list) or len(enum) == 0:
                errors.push("%s.enum: expected a non-empty array" % p)
            else:
                seen = set()
                for value in enum:
                    try:
                        key = canonical_key(value)["key"]
                    except ValueError as error:
                        errors.push("%s.enum: %s" % (p, error))
                        break
                    if key in seen:
                        errors.push("%s.enum: entries must be unique" % p)
                        break
                    seen.add(key)
        if "items" in node:
            check(node["items"], "%s.items" % p)
        for keyword in ("minItems", "minLength"):
            if keyword in node and (not number_is_integer(node[keyword]) or node[keyword] < 0):
                errors.push("%s.%s: expected a non-negative integer" % (p, keyword))
        if "minimum" in node and not is_finite_number(node["minimum"]):
            errors.push("%s.minimum: expected a finite number" % p)
        if "pattern" in node:
            if not isinstance(node["pattern"], str):
                errors.push("%s.pattern: expected string" % p)
            else:
                try:
                    re.compile(node["pattern"])
                except re.error:
                    errors.push("%s.pattern: invalid regular expression" % p)
        if "uniqueItems" in node and not isinstance(node["uniqueItems"], bool):
            errors.push("%s.uniqueItems: expected boolean" % p)
        if "visibleContent" in node:
            if not isinstance(node["visibleContent"], bool):
                errors.push("%s.visibleContent: expected boolean" % p)
            elif node["visibleContent"] is True and node.get("type") != "string":
                errors.push('%s.visibleContent: requires type "string"' % p)
        if "oneOf" in node:
            one_of = node["oneOf"]
            if not isinstance(one_of, list) or len(one_of) == 0:
                errors.push("%s.oneOf: expected a non-empty array" % p)
            else:
                for index, branch in enumerate(one_of):
                    check(branch, "%s.oneOf[%d]" % (p, index))

    check(schema, location)
    return errors


def find_discriminator(schema):
    if "properties" not in schema or not isinstance(schema["properties"], dict):
        return None
    for key in js_object_keys(schema["properties"]):
        sub_schema = schema["properties"][key]
        if isinstance(sub_schema, dict) and "const" in sub_schema:
            return {"key": key, "value": sub_schema["const"]}
    return None


def validate(value, schema, p, errors):
    if len(errors) >= VALIDATION_ERRORS:
        return
    if "oneOf" in schema:
        results = [collect_unchecked(value, branch, p) for branch in schema["oneOf"]]
        passing_indexes = [index for index, branch_errors in enumerate(results) if len(branch_errors) == 0]

        if len(passing_indexes) != 1:
            errors.push("%s: must match exactly one schema in oneOf; matched %d" % (p, len(passing_indexes)))
            if len(passing_indexes) == 0 and isinstance(value, dict):
                matching = [
                    index
                    for index, branch in enumerate(schema["oneOf"])
                    if (lambda d: d and d["key"] in value and deep_equal(value[d["key"]], d["value"]))(find_discriminator(branch))
                ]
                if len(matching) == 1:
                    errors.push(*results[matching[0]])

    if "const" in schema and not deep_equal(value, schema["const"]):
        errors.push("%s: must equal %s, got %s" % (p, safe_quote(schema["const"]), safe_quote(value)))
    if "enum" in schema and not any(deep_equal(value, allowed) for allowed in schema["enum"]):
        allowed = ", ".join(safe_quote(entry) for entry in schema["enum"])
        errors.push("%s: invalid value %s (expected one of %s)" % (p, safe_quote(value), allowed))

    if "type" in schema and type_of(value) != schema["type"] and not (
        schema["type"] == "integer" and type_of(value) == "number" and number_is_integer(value)
    ):
        errors.push("%s: expected %s, got %s" % (p, schema["type"], type_of(value)))
        return

    if type_of(value) == "object":
        for req in schema["required"] if "required" in schema else []:
            if req not in value:
                errors.push("%s: missing required field %s" % (p, safe_quote(req)))
        for key in js_object_keys(value):
            if "properties" in schema and key in schema["properties"]:
                validate(value[key], schema["properties"][key], property_path(p, key), errors)
            elif schema.get("additionalProperties") is False:
                errors.push("%s: unexpected field %s" % (p, safe_quote(key)))

    if isinstance(value, list):
        if "minItems" in schema and len(value) < schema["minItems"]:
            errors.push("%s: must have at least %s item(s), got %d" % (p, js_number_to_string(schema["minItems"]), len(value)))
        if schema.get("uniqueItems") is True:
            seen = set()
            set_bytes = 0
            for index in range(len(value)):
                try:
                    canonical = canonical_key(value[index])
                except ValueError as error:
                    errors.push("%s[%d]: %s" % (p, index, error))
                    break
                if canonical["key"] in seen:
                    errors.push("%s: items must be unique; duplicate at index %d" % (p, index))
                    continue
                set_bytes += canonical["bytes"]
                if set_bytes > LIMITS["uniqueSetBytes"]:
                    errors.push("%s: canonical uniqueness set exceeds %d byte limit" % (p, LIMITS["uniqueSetBytes"]))
                    break
                seen.add(canonical["key"])
        if "items" in schema:
            for index, item in enumerate(value):
                validate(item, schema["items"], "%s[%d]" % (p, index), errors)

    if isinstance(value, str):
        if "minLength" in schema and code_point_length(value) < schema["minLength"]:
            errors.push("%s: must have at least %s character(s)" % (p, js_number_to_string(schema["minLength"])))
        if schema.get("visibleContent") is True:
            if not has_valid_unicode_scalar_values(value):
                errors.push("%s: must contain only valid Unicode scalar values" % p)
            elif not visible_content_match(value):
                errors.push("%s: must contain a visible character" % p)
        if "pattern" in schema and re.compile(schema["pattern"]).search(value) is None:
            errors.push("%s: must match pattern %s" % (p, js_json_stringify(schema["pattern"])))

    if is_number(value) and "minimum" in schema and value < schema["minimum"]:
        errors.push("%s: must be at least %s, got %s" % (p, js_number_to_string(schema["minimum"]), js_number_to_string(value)))


def collect_unchecked(value, schema, p):
    errors = create_error_list(VALIDATION_ERRORS)
    validate(value, schema, p, errors)
    return errors


def collect(value, schema, p="$data"):
    limit_errors = collect_data_limit_errors(value, p)
    if len(limit_errors) > 0:
        return limit_errors
    return collect_unchecked(value, schema, p)


def is_safe_relative_source_path(value):
    return is_safe_relative_path(value)


def collect_finding_semantic_errors(findings):
    errors = create_error_list(VALIDATION_ERRORS)
    if not isinstance(findings, list):
        return errors

    fingerprints = {}
    previous_fingerprint = None

    for index, finding in enumerate(findings):
        if len(errors) >= VALIDATION_ERRORS:
            return errors
        if not isinstance(finding, dict):
            continue
        base = "$[%d]" % index

        if isinstance(finding.get("fingerprint"), str):
            fingerprint = finding["fingerprint"]
            if fingerprint in fingerprints:
                errors.push("%s.fingerprint: duplicate of $[%d].fingerprint" % (base, fingerprints[fingerprint]))
            else:
                fingerprints[fingerprint] = index
            if previous_fingerprint is not None and previous_fingerprint > fingerprint:
                errors.push("%s.fingerprint: findings must be sorted lexicographically" % base)
            previous_fingerprint = fingerprint

        for field in ("trace", "evidence"):
            if field not in finding or not isinstance(finding[field], list):
                continue
            for entry_index, entry in enumerate(finding[field]):
                if not isinstance(entry, dict):
                    continue
                if "line" in entry and (not number_is_integer(entry["line"]) or entry["line"] < 1):
                    errors.push("%s.%s[%d].line: must be a positive integer" % (base, field, entry_index))
                if "file" in entry and not is_safe_relative_source_path(entry["file"]):
                    errors.push("%s.%s[%d].file: must be a safe repository-relative source path" % (base, field, entry_index))

        remediation = finding.get("remediation")
        if isinstance(remediation, dict) and isinstance(remediation.get("code_changes"), list):
            for change_index, change in enumerate(remediation["code_changes"]):
                if isinstance(change, dict) and "file_name" in change and not is_safe_relative_source_path(change["file_name"]):
                    errors.push("%s.remediation.code_changes[%d].file_name: must be a safe repository-relative source path" % (base, change_index))

        if isinstance(finding.get("trace"), list) and len(finding["trace"]) == 1:
            first = finding["trace"][0]
            kind = get_prop(first, "kind")
            if kind not in ("entrypoint", "sink"):
                errors.push('%s.trace[0].kind: a one-line trace must be "entrypoint" or "sink"' % base)
        elif isinstance(finding.get("trace"), list) and len(finding["trace"]) > 1:
            trace = finding["trace"]
            last = len(trace) - 1
            if truthy_trace(trace[0]) and get_prop(trace[0], "kind") != "entrypoint":
                errors.push('%s.trace[0].kind: must be "entrypoint", got %s' % (base, safe_quote(get_prop(trace[0], "kind"))))
            if truthy_trace(trace[last]) and get_prop(trace[last], "kind") != "sink":
                errors.push('%s.trace[%d].kind: must be "sink", got %s' % (base, last, safe_quote(get_prop(trace[last], "kind"))))
            for trace_index in range(1, last):
                entry = trace[trace_index]
                if truthy_trace(entry) and get_prop(entry, "kind") != "propagation":
                    errors.push('%s.trace[%d].kind: must be "propagation", got %s' % (base, trace_index, safe_quote(get_prop(entry, "kind"))))

        verdict = finding.get("verdict")
        if verdict == "confirmed":
            for forbidden in ("claimed_root_cause", "blockers", "validation_plan", "reason"):
                if forbidden in finding:
                    errors.push("%s: confirmed finding must not contain %s" % (base, safe_quote(forbidden)))
            execution = finding.get("execution")
            if (
                not isinstance(execution, dict)
                or not isinstance(execution.get("observed_result"), str)
                or not has_visible_prose(execution["observed_result"])
            ):
                errors.push("%s: confirmed finding requires a visible execution observed_result" % base)
            remediation_value = finding.get("remediation")
            if (
                not isinstance(remediation_value, dict)
                or not isinstance(remediation_value.get("strategy"), str)
                or not has_visible_prose(remediation_value["strategy"])
            ):
                errors.push("%s: confirmed finding requires visible remediation" % base)
            severity = finding.get("severity")
            impact = severity.get("impact") if isinstance(severity, dict) else None
            overall = severity.get("overall_severity") if isinstance(severity, dict) else None
            impact_score = impact.get("score") if isinstance(impact, dict) else None
            if (
                set_has(SEVERITY_RANK, overall)
                and set_has(SEVERITY_RANK, impact_score)
                and SEVERITY_RANK[overall] > SEVERITY_RANK[impact_score]
            ):
                errors.push("%s.severity.overall_severity: cannot exceed demonstrated impact %s" % (base, safe_quote(impact_score)))
        elif verdict == "needs_validation":
            if "severity" in finding:
                errors.push('%s: needs_validation finding must not contain "severity"' % base)
            for forbidden in ("execution", "remediation", "reason", "root_cause"):
                if forbidden in finding:
                    errors.push("%s: needs_validation finding must not contain %s" % (base, safe_quote(forbidden)))
            plan = finding.get("validation_plan")
            has_local_plan = isinstance(plan, dict) and isinstance(plan.get("local"), str) and has_visible_prose(plan["local"])
            has_deployment_plan = isinstance(plan, dict) and isinstance(plan.get("deployment"), str) and has_visible_prose(plan["deployment"])
            if not has_local_plan and not has_deployment_plan:
                errors.push("%s.validation_plan: requires at least one visible local or deployment plan" % base)
        elif verdict == "rejected":
            for forbidden in ("severity", "execution", "remediation", "blockers", "validation_plan", "root_cause"):
                if forbidden in finding:
                    errors.push("%s: rejected finding must not contain %s" % (base, safe_quote(forbidden)))

    return errors


def validate_document(findings, schema):
    schema_errors = collect_schema_errors(schema)
    if len(schema_errors) > 0:
        return schema_errors
    limit_errors = collect_data_limit_errors(findings, "$")
    if len(limit_errors) > 0:
        return limit_errors
    errors = collect_unchecked(findings, schema, "$")
    if len(errors) < VALIDATION_ERRORS:
        errors.push(*collect_finding_semantic_errors(findings))
    return errors


def load_schema(schema_path):
    with open(schema_path, "r", encoding="utf-8") as handle:
        schema = json.load(handle)
    errors = collect_schema_errors(schema)
    if len(errors) > 0:
        raise ValueError("unsupported or invalid report schema:\n" + "\n".join(errors))
    return schema


def enforce_json_text_limits(contents):
    containers = []
    in_string = False
    escaped = False

    def mark_array_item():
        container = containers[-1] if containers else None
        if not container or container["type"] != "array" or not container["expectsItem"]:
            return
        container["expectsItem"] = False
        container["items"] += 1
        if container["items"] > LIMITS["arrayItems"]:
            raise JsonStructureError("input exceeds %d item array limit" % LIMITS["arrayItems"])

    for index in range(len(contents)):
        character = contents[index]
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue

        if character == '"':
            mark_array_item()
            in_string = True
        elif character in "[{":
            mark_array_item()
            if len(containers) >= LIMITS["nestingDepth"]:
                raise JsonStructureError("input exceeds %d level nesting depth limit" % LIMITS["nestingDepth"])
            containers.append({
                "type": "array" if character == "[" else "object",
                "expectsItem": character == "[",
                "items": 0,
            })
        elif character in "]}":
            if containers:
                containers.pop()
        elif character == ",":
            container = containers[-1] if containers else None
            if container and container["type"] == "array":
                container["expectsItem"] = True
        elif not is_js_whitespace(character):
            mark_array_item()


def emit(stream, text):
    stream.write(text)


def run(file):
    if not file:
        sys.stderr.write("Usage: python3 validate-findings.py <path-to-findings.json>\n")
        return 1

    try:
        schema = load_schema(os.path.join(os.path.dirname(os.path.abspath(__file__)), "report-schema.json"))
    except Exception as error:  # noqa: BLE001 - mirror the Node catch-all
        sys.stderr.write("Failed to load report-schema.json: %s\n" % error)
        return 1

    try:
        contents = read_file_within_limit(file, LIMITS["inputBytes"])
    except Exception as error:  # noqa: BLE001
        reason = str(error) if isinstance(error, SafeInputError) else "input could not be opened or read safely"
        sys.stderr.write("Failed to read findings JSON: %s\n" % reason)
        return 1

    try:
        enforce_json_text_limits(contents)
    except Exception as error:  # noqa: BLE001
        reason = str(error) if isinstance(error, JsonStructureError) else "invalid JSON structure"
        sys.stderr.write("Failed to parse findings JSON: %s\n" % reason)
        return 1

    try:
        findings = load_json_text(contents)
    except Exception:  # noqa: BLE001
        sys.stderr.write("Failed to parse findings JSON: invalid JSON syntax\n")
        return 1

    try:
        errors = validate_document(findings, schema)
    except Exception:  # noqa: BLE001
        sys.stderr.write("Failed to validate findings JSON: unexpected validation error\n")
        return 1

    for message in errors:
        sys.stderr.write("ERROR: %s\n" % escape_unsafe_diagnostic_characters(message))
    if len(errors) > 0:
        cap = "; output capped at %d" % VALIDATION_ERRORS if len(errors) == VALIDATION_ERRORS else ""
        sys.stderr.write("FAIL: %d validation error(s)%s\n" % (len(errors), cap))
        return 1
    sys.stdout.write("PASS: %d findings valid\n" % (len(findings) if isinstance(findings, list) else 0))
    return 0


def main():
    sys.exit(run(sys.argv[1] if len(sys.argv) > 1 else None))


if __name__ == "__main__":
    main()
