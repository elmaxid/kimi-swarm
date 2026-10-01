#!/usr/bin/env python3
"""Validates coverage-ledger.json and its canonical coverage IDs.

Usage: python3 validate-coverage-ledger.py <path-to-coverage-ledger.json>

Dependency-free Python 3 port of validate-coverage-ledger.cjs.
"""

import os
import re
import sys
import unicodedata

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _validate_common import (  # noqa: E402
    JsonStructureError,
    SafeInputError,
    collection_has,
    create_error_list,
    escape_unsafe_diagnostic_characters,
    has_visible_prose,
    is_safe_relative_path,
    is_visible_text,
    get_prop,
    set_has,
    js_json_stringify_value,
    js_object_keys,
    load_json_text,
    number_is_integer,
    path_forbidden_match,
    read_file_within_limit,
    safe_quote,
)

# Conservative bounds apply before JSON.parse and again to the parsed document.
LIMITS = {
    "inputBytes": 5 * 1024 * 1024,
    "units": 10000,
    "collectionItems": 1000,
    "objectFields": 1000,
    "nestingDepth": 64,
    "preflightValues": 500000,
    "validationErrors": 100,
}
MAX_INPUT_BYTES = LIMITS["inputBytes"]
MAX_UNITS = LIMITS["units"]
MAX_LIST_ITEMS = LIMITS["collectionItems"]
MAX_TEXT_LENGTH = 4096
VALIDATION_ERRORS = LIMITS["validationErrors"]
REQUIRED_FIELDS = [
    "coverage_id",
    "canonical_refs",
    "surface",
    "boundary",
    "subsystem",
    "attack_class",
    "starting_paths",
    "ordinary_attack_class_block",
    "selected_companion_blocks",
    "excluded_blocks",
    "prior_status",
    "attempts",
    "wave",
    "status",
    "agent_id",
    "reviewed_paths",
    "local_checks",
    "result_fingerprints",
    "unresolved",
]
REF_FIELDS = ["surface", "boundary", "subsystem", "attack_class"]
STATUSES = frozenset([
    "planned",
    "not_applicable",
    "out_of_scope",
    "in_progress",
    "covered",
    "candidate",
    "blocked",
    "deferred",
])
ATTEMPT_STATUSES = frozenset(["covered", "candidate", "blocked"])
ATTEMPT_FIELDS = [
    "wave",
    "status",
    "agent_id",
    "reviewed_paths",
    "local_checks",
    "result_fingerprints",
    "unresolved",
    "reassignment_reason",
]
PRIOR_STATUSES = frozenset([
    "new",
    "prior_confirmed_same_source",
    "prior_confirmed_changed_source",
    "prior_needs_validation",
    "prior_deferred",
    "prior_blocked",
    "prior_out_of_scope",
    "prior_covered_same_source",
    "prior_covered_changed_source",
    "prior_rejected_claim_changed",
    "none",
])
FINGERPRINT_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$")
AGENT_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
WINDOWS_RESERVED_AGENT_ID = re.compile(r"^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])$")


def _is_object(value):
    return isinstance(value, dict)


def _ordered_unique(values):
    """Unique values in first-seen order (mirrors a JavaScript ``Set``)."""
    seen = []
    for value in values:
        if value not in seen:
            seen.append(value)
    return seen


def preflight_json_text(contents):
    containers = []
    root_state = "value"
    in_string = False
    escaped = False
    total_values = 0

    def fail(message):
        raise JsonStructureError("input " + message)

    def current_container():
        return containers[-1] if containers else None

    def count_value():
        nonlocal total_values
        total_values += 1
        if total_values > LIMITS["preflightValues"]:
            fail("exceeds %d total value limit" % LIMITS["preflightValues"])

    def begin_value():
        nonlocal root_state
        container = current_container()
        if container is None:
            if root_state != "value":
                fail("has malformed JSON structure")
            root_state = "end"
        elif container["type"] == "array":
            if container["state"] not in ("firstValueOrEnd", "value"):
                fail("has malformed JSON array structure")
            container["items"] += 1
            limit = MAX_UNITS if container.get("topLevel") else LIMITS["collectionItems"]
            if container["items"] > limit:
                if container.get("topLevel"):
                    fail("exceeds %d top-level unit limit" % limit)
                fail("exceeds %d item array limit" % limit)
            container["state"] = "commaOrEnd"
        else:
            if container["state"] != "value":
                fail("has malformed JSON object structure")
            container["state"] = "commaOrEnd"
        count_value()

    def begin_string():
        nonlocal in_string
        container = current_container()
        if (
            container is not None
            and container["type"] == "object"
            and container["state"] in ("firstKeyOrEnd", "key")
        ):
            container["fields"] += 1
            if container["fields"] > LIMITS["objectFields"]:
                fail("exceeds %d field object limit" % LIMITS["objectFields"])
            container["state"] = "colon"
        else:
            begin_value()
        in_string = True

    def begin_container(container_type):
        begin_value()
        if len(containers) >= LIMITS["nestingDepth"]:
            fail("exceeds nesting depth limit %d" % LIMITS["nestingDepth"])
        containers.append(
            {
                "type": container_type,
                "state": "firstValueOrEnd" if container_type == "array" else "firstKeyOrEnd",
                "items": 0,
                "fields": 0,
                "topLevel": len(containers) == 0,
            }
        )

    def close_container(container_type):
        container = current_container()
        if not container or container["type"] != container_type:
            fail("has mismatched JSON containers")
        if container_type == "array":
            can_close = container["state"] in ("firstValueOrEnd", "commaOrEnd")
        else:
            can_close = container["state"] in ("firstKeyOrEnd", "commaOrEnd")
        if not can_close:
            fail("has malformed JSON %s structure" % container_type)
        containers.pop()

    def is_token_delimiter(character):
        return (
            character in (" ", "\t", "\r", "\n")
            or character in ",:[]{}"
            or character == '"'
        )

    index = 0
    length = len(contents)
    while index < length:
        character = contents[index]
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            index += 1
            continue
        if character in (" ", "\t", "\r", "\n"):
            index += 1
            continue

        if character == '"':
            begin_string()
        elif character == "[":
            begin_container("array")
        elif character == "{":
            begin_container("object")
        elif character == "]":
            close_container("array")
        elif character == "}":
            close_container("object")
        elif character == ":":
            container = current_container()
            if not container or container["type"] != "object" or container["state"] != "colon":
                fail("has malformed JSON object structure")
            container["state"] = "value"
        elif character == ",":
            container = current_container()
            if not container or container["state"] != "commaOrEnd":
                fail("has malformed JSON collection structure")
            container["state"] = "value" if container["type"] == "array" else "key"
        else:
            begin_value()
            while index + 1 < length and not is_token_delimiter(contents[index + 1]):
                index += 1
        index += 1

    if in_string:
        fail("has an unterminated JSON string")
    if len(containers) > 0:
        fail("has truncated JSON structure")
    if root_state != "end":
        fail("has no JSON value")


def preflight_document(root):
    errors = create_error_list(VALIDATION_ERRORS)
    stack = [(root, 0, "$")]
    visited = 0

    while stack:
        value, depth, location = stack.pop()
        visited += 1
        if visited > LIMITS["preflightValues"]:
            errors.push("$: exceeds %d total values" % LIMITS["preflightValues"])
            return errors
        if value is None or not isinstance(value, (dict, list)):
            continue
        if depth >= LIMITS["nestingDepth"]:
            errors.push("%s: exceeds nesting depth limit %d" % (location, LIMITS["nestingDepth"]))
            return errors

        if isinstance(value, list):
            limit = MAX_UNITS if location == "$" else MAX_LIST_ITEMS
            if len(value) > limit:
                errors.push("%s: exceeds %d entries" % (location, limit))
                return errors
            for index in range(len(value) - 1, -1, -1):
                stack.append((value[index], depth + 1, "%s[%d]" % (location, index)))
            continue

        keys = js_object_keys(value)
        if len(keys) > LIMITS["objectFields"]:
            errors.push("%s: exceeds %d object fields" % (location, LIMITS["objectFields"]))
            return errors
        for index in range(len(keys) - 1, -1, -1):
            key = keys[index]
            stack.append((value[key], depth + 1, "%s{%d}" % (location, index)))

    return errors


def is_canonical_ref(value):
    return (
        is_visible_text(value, 1024)
        and not path_forbidden_match(value)
        and unicodedata.normalize("NFC", value) == value
    )


def encode_canonical_ref(value):
    if not is_canonical_ref(value):
        raise TypeError("invalid canonical reference")
    encoded = []
    for byte in value.encode("utf-8"):
        unreserved = (
            0x41 <= byte <= 0x5A
            or 0x61 <= byte <= 0x7A
            or 0x30 <= byte <= 0x39
            or byte in (0x2D, 0x2E, 0x5F, 0x7E)
        )
        encoded.append(chr(byte) if unreserved else "%%%02X" % byte)
    return "".join(encoded)


def canonical_coverage_id(refs):
    if not _is_object(refs):
        raise TypeError("canonical_refs must be an object")
    fields = REF_FIELDS + ["lifecycle"] if "lifecycle" in refs else list(REF_FIELDS)
    if len(refs) != len(fields) or any(field not in refs for field in fields):
        raise TypeError("canonical_refs has missing or unexpected fields")
    return "::".join(encode_canonical_ref(refs[field]) for field in fields)


def is_safe_agent_id(value):
    return (
        isinstance(value, str)
        and AGENT_ID_PATTERN.match(value) is not None
        and WINDOWS_RESERVED_AGENT_ID.match(value) is None
    )


def is_owned_artifact_path(value, agent_id):
    if not is_safe_agent_id(agent_id) or not is_safe_relative_path(value):
        return False
    prefix = "agents/%s/artifacts/" % agent_id
    return value.startswith(prefix) and len(value) > len(prefix)


def validate_string_array(value, location, errors, allow_empty=True, fingerprint=False, path_value=False):
    if not isinstance(value, list):
        errors.push("%s: expected array" % location)
        return
    if not allow_empty and len(value) == 0:
        errors.push("%s: must not be empty" % location)
    if len(value) > MAX_LIST_ITEMS:
        errors.push("%s: exceeds %d entries" % (location, MAX_LIST_ITEMS))
    seen = set()
    for index, entry in enumerate(value[:MAX_LIST_ITEMS]):
        entry_location = "%s[%d]" % (location, index)
        valid = is_safe_relative_path(entry) if path_value else is_visible_text(entry)
        if not valid:
            errors.push("%s: invalid %s" % (entry_location, "repository-relative path" if path_value else "text"))
        if fingerprint and isinstance(entry, str) and FINGERPRINT_PATTERN.match(entry) is None:
            errors.push("%s: invalid fingerprint" % entry_location)
        if isinstance(entry, str) and entry in seen:
            errors.push("%s: duplicate entry" % entry_location)
        if isinstance(entry, str):
            seen.add(entry)


def validate_checks(value, location, errors):
    if not isinstance(value, list):
        errors.push("%s: expected array" % location)
        return
    if len(value) > MAX_LIST_ITEMS:
        errors.push("%s: exceeds %d entries" % (location, MAX_LIST_ITEMS))
    for index, check in enumerate(value[:MAX_LIST_ITEMS]):
        base = "%s[%d]" % (location, index)
        if not _is_object(check):
            errors.push("%s: expected object" % base)
            continue
        for field in ("agent_id", "reviewed_paths", "invariant", "method", "result", "artifact"):
            if field not in check:
                errors.push("%s: missing required field %s" % (base, safe_quote(field)))
        if not is_safe_agent_id(check.get("agent_id")):
            errors.push("%s.agent_id: expected a canonical lowercase agent ID" % base)
        validate_string_array(check.get("reviewed_paths"), "%s.reviewed_paths" % base, errors, allow_empty=False, path_value=True)
        if not is_visible_text(check.get("invariant")):
            errors.push("%s.invariant: invalid text" % base)
        if check.get("method") != "source" and check.get("method") != "local":
            errors.push('%s.method: expected "source" or "local"' % base)
        if not is_visible_text(check.get("result")):
            errors.push("%s.result: invalid text" % base)
        artifact = get_prop(check, "artifact")
        if check.get("method") == "source" and artifact is not None:
            errors.push("%s.artifact: source-only check must use null" % base)
        elif check.get("method") == "local":
            if not is_owned_artifact_path(artifact, check.get("agent_id")):
                owner = check.get("agent_id") if is_safe_agent_id(check.get("agent_id")) else "<agent-id>"
                errors.push("%s.artifact: local check requires an artifact owned by agent %s" % (base, safe_quote(owner)))
        elif (
            check.get("method") != "source" and check.get("method") != "local"
            and artifact is not None
            and not is_safe_relative_path(artifact)
        ):
            errors.push("%s.artifact: expected null or a safe output-relative path" % base)


def validate_reviewed_path_ownership(unit, base, errors):
    if not isinstance(unit.get("reviewed_paths"), list) or not isinstance(unit.get("local_checks"), list):
        return
    aggregate_paths = _ordered_unique(value for value in unit["reviewed_paths"] if isinstance(value, str))
    owned_paths = []
    for check in unit["local_checks"]:
        if not _is_object(check) or not isinstance(check.get("reviewed_paths"), list):
            continue
        for reviewed_path in check["reviewed_paths"]:
            if isinstance(reviewed_path, str) and reviewed_path not in owned_paths:
                owned_paths.append(reviewed_path)
    for reviewed_path in aggregate_paths:
        if reviewed_path not in owned_paths:
            errors.push("%s.reviewed_paths: %s has no check owner" % (base, safe_quote(reviewed_path)))
    for reviewed_path in owned_paths:
        if reviewed_path not in aggregate_paths:
            errors.push("%s.local_checks: owned path %s is absent from aggregate reviewed_paths" % (base, safe_quote(reviewed_path)))


def validate_excluded_blocks(value, location, errors):
    if not isinstance(value, list):
        errors.push("%s: expected array" % location)
        return
    if len(value) > MAX_LIST_ITEMS:
        errors.push("%s: exceeds %d entries" % (location, MAX_LIST_ITEMS))
    seen = set()
    for index, entry in enumerate(value[:MAX_LIST_ITEMS]):
        base = "%s[%d]" % (location, index)
        if not _is_object(entry):
            errors.push("%s: expected object" % base)
            continue
        if not is_visible_text(entry.get("block")):
            errors.push("%s.block: invalid text" % base)
        if not is_visible_text(entry.get("reason")):
            errors.push("%s.reason: invalid text" % base)
        block = entry.get("block")
        if isinstance(block, str) and block in seen:
            errors.push("%s.block: duplicate entry" % base)
        if isinstance(block, str):
            seen.add(block)


def semantic_key(unit):
    return js_json_stringify_value([
        get_prop(unit, "surface"),
        get_prop(unit, "boundary"),
        get_prop(unit, "subsystem"),
        get_prop(unit, "attack_class"),
        get_prop(unit, "lifecycle") if "lifecycle" in unit else None,
    ])


def has_valid_semantic_fields(unit):
    return (
        all(is_visible_text(unit.get(field)) for field in ("surface", "boundary", "subsystem", "attack_class"))
        and ("lifecycle" not in unit or is_visible_text(unit.get("lifecycle")))
    )


def require_empty_array(unit, field, base, errors):
    if isinstance(unit.get(field), list) and len(unit[field]) > 0:
        errors.push("%s.%s: unit with status %s must keep this array empty" % (base, field, safe_quote(get_prop(unit, "status"))))


def require_nonempty_array(unit, field, base, errors):
    if not isinstance(unit.get(field), list) or len(unit[field]) == 0:
        errors.push("%s.%s: unit with status %s requires entries" % (base, field, safe_quote(get_prop(unit, "status"))))


def validate_state_invariants(unit, base, errors):
    def empty_evidence():
        require_empty_array(unit, "reviewed_paths", base, errors)
        require_empty_array(unit, "local_checks", base, errors)

    def require_owner():
        if not is_safe_agent_id(get_prop(unit, "agent_id")):
            errors.push("%s.agent_id: unit with status %s requires a canonical lowercase agent ID" % (base, safe_quote(get_prop(unit, "status"))))

    if get_prop(unit, "status") != "candidate":
        require_empty_array(unit, "result_fingerprints", base, errors)

    status = get_prop(unit, "status")
    if status == "planned":
        if get_prop(unit, "agent_id") is not None:
            errors.push("%s.agent_id: planned unit must be unassigned" % base)
        empty_evidence()
        require_empty_array(unit, "unresolved", base, errors)
    elif status in ("not_applicable", "out_of_scope", "deferred"):
        if get_prop(unit, "agent_id") is not None:
            errors.push("%s.agent_id: unit with status %s must be unassigned" % (base, safe_quote(status)))
        empty_evidence()
        require_nonempty_array(unit, "unresolved", base, errors)
    elif status == "in_progress":
        require_owner()
        empty_evidence()
        require_empty_array(unit, "unresolved", base, errors)
    elif status == "blocked":
        require_owner()
        require_nonempty_array(unit, "reviewed_paths", base, errors)
        require_nonempty_array(unit, "local_checks", base, errors)
        require_nonempty_array(unit, "unresolved", base, errors)
    elif status == "covered":
        require_owner()
        require_nonempty_array(unit, "reviewed_paths", base, errors)
        require_nonempty_array(unit, "local_checks", base, errors)
        require_empty_array(unit, "unresolved", base, errors)
    elif status == "candidate":
        require_owner()
        require_nonempty_array(unit, "reviewed_paths", base, errors)
        require_nonempty_array(unit, "local_checks", base, errors)
        require_nonempty_array(unit, "result_fingerprints", base, errors)


def validate_attempts(value, unit, base, errors):
    if not isinstance(value, list):
        errors.push("%s.attempts: expected array" % base)
        return
    if len(value) > MAX_LIST_ITEMS:
        errors.push("%s.attempts: exceeds %d entries" % (base, MAX_LIST_ITEMS))

    prior_owners = set()
    prior_artifacts = set()
    previous_wave = 0
    for index, attempt in enumerate(value[:MAX_LIST_ITEMS]):
        attempt_base = "%s.attempts[%d]" % (base, index)
        if not _is_object(attempt):
            errors.push("%s: expected object" % attempt_base)
            continue
        for field in ATTEMPT_FIELDS:
            if field not in attempt:
                errors.push("%s: missing required field %s" % (attempt_base, safe_quote(field)))
        wave = attempt.get("wave")
        if not number_is_integer(wave) or wave < 1:
            errors.push("%s.wave: expected a positive integer" % attempt_base)
        else:
            if wave <= previous_wave:
                errors.push("%s.wave: archived attempt waves must be strictly increasing" % attempt_base)
            unit_wave = get_prop(unit, "wave")
            if number_is_integer(unit_wave) and wave >= unit_wave:
                errors.push("%s.wave: archived attempt wave must precede current wave %s" % (attempt_base, safe_quote(unit_wave)))
            previous_wave = wave
        if not set_has(ATTEMPT_STATUSES, attempt.get("status")):
            errors.push('%s.status: expected "covered", "candidate", or "blocked"' % attempt_base)
        has_fresh_owner = False
        if not is_safe_agent_id(attempt.get("agent_id")):
            errors.push("%s.agent_id: archived attempt requires a canonical lowercase agent ID" % attempt_base)
        elif is_safe_agent_id(attempt.get("agent_id")) and attempt.get("agent_id") in prior_owners:
            errors.push("%s.agent_id: assignment owner must be fresh for each attempt" % attempt_base)
        else:
            has_fresh_owner = True
        validate_string_array(attempt.get("reviewed_paths"), "%s.reviewed_paths" % attempt_base, errors, path_value=True)
        validate_checks(attempt.get("local_checks"), "%s.local_checks" % attempt_base, errors)
        validate_reviewed_path_ownership(attempt, attempt_base, errors)
        validate_string_array(attempt.get("result_fingerprints"), "%s.result_fingerprints" % attempt_base, errors, fingerprint=True)
        validate_string_array(attempt.get("unresolved"), "%s.unresolved" % attempt_base, errors)
        if not is_visible_text(attempt.get("reassignment_reason")):
            errors.push("%s.reassignment_reason: invalid text" % attempt_base)
        validate_state_invariants(attempt, attempt_base, errors)

        local_checks = attempt.get("local_checks")
        if isinstance(local_checks, list):
            for check_index, check in enumerate(local_checks):
                if not _is_object(check):
                    continue
                if is_safe_agent_id(check.get("agent_id")) and check.get("agent_id") in prior_owners:
                    errors.push("%s.local_checks[%d].agent_id: prior assignment owner evidence must remain in its earlier attempt" % (attempt_base, check_index))
                artifact = get_prop(check, "artifact")
                if isinstance(artifact, str) and artifact in prior_artifacts:
                    errors.push("%s.local_checks[%d].artifact: artifact from an earlier attempt cannot be reused" % (attempt_base, check_index))
                if check.get("method") == "local" and isinstance(artifact, str):
                    prior_artifacts.add(artifact)
        if has_fresh_owner:
            prior_owners.add(attempt.get("agent_id"))

    if is_safe_agent_id(get_prop(unit, "agent_id")) and get_prop(unit, "agent_id") in prior_owners:
        errors.push("%s.agent_id: current assignment owner must be fresh after reassignment" % base)
    unit_local_checks = unit.get("local_checks")
    if isinstance(unit_local_checks, list):
        for index, check in enumerate(unit_local_checks):
            if not _is_object(check):
                continue
            if is_safe_agent_id(check.get("agent_id")) and check.get("agent_id") in prior_owners:
                errors.push("%s.local_checks[%d].agent_id: prior assignment owner evidence must remain in its archived attempt" % (base, index))
            artifact = get_prop(check, "artifact")
            if isinstance(artifact, str) and artifact in prior_artifacts:
                errors.push("%s.local_checks[%d].artifact: artifact from an archived attempt cannot be reused" % (base, index))


def collect_unit_errors(unit, index):
    errors = create_error_list(VALIDATION_ERRORS)
    base = "$[%d]" % index
    if not _is_object(unit):
        return ["%s: expected object" % base]

    for field in REQUIRED_FIELDS:
        if field not in unit:
            errors.push("%s: missing required field %s" % (base, safe_quote(field)))
    for field in ("surface", "boundary", "subsystem", "attack_class"):
        if not is_visible_text(unit.get(field)):
            errors.push("%s.%s: invalid text" % (base, field))
    if "lifecycle" in unit and not is_visible_text(unit.get("lifecycle")):
        errors.push("%s.lifecycle: invalid text" % base)

    expected_id = None
    canonical_refs = unit.get("canonical_refs")
    if not _is_object(canonical_refs):
        errors.push("%s.canonical_refs: expected object" % base)
    else:
        expected_fields = REF_FIELDS + ["lifecycle"] if "lifecycle" in canonical_refs else list(REF_FIELDS)
        for field in expected_fields:
            if field not in canonical_refs:
                errors.push("%s.canonical_refs: missing required field %s" % (base, safe_quote(field)))
            elif not is_canonical_ref(canonical_refs[field]):
                errors.push("%s.canonical_refs.%s: invalid canonical reference" % (base, field))
        if any(field not in expected_fields for field in canonical_refs):
            errors.push("%s.canonical_refs: contains unexpected fields" % base)
        if ("lifecycle" in unit) != ("lifecycle" in canonical_refs):
            errors.push("%s: lifecycle and canonical_refs.lifecycle must appear together" % base)
        try:
            expected_id = canonical_coverage_id(canonical_refs)
        except TypeError:
            # The specific reference errors above are more useful.
            pass
    if not is_visible_text(unit.get("coverage_id"), 65536):
        errors.push("%s.coverage_id: invalid text" % base)
    elif expected_id is not None and unit.get("coverage_id") != expected_id:
        errors.push("%s.coverage_id: expected canonical ID %s" % (base, safe_quote(expected_id)))

    validate_string_array(unit.get("starting_paths"), "%s.starting_paths" % base, errors, allow_empty=False, path_value=True)
    ordinary_block = get_prop(unit, "ordinary_attack_class_block")
    if ordinary_block is not None and not is_visible_text(ordinary_block):
        errors.push("%s.ordinary_attack_class_block: expected null or non-empty text" % base)
    validate_string_array(unit.get("selected_companion_blocks"), "%s.selected_companion_blocks" % base, errors)
    validate_excluded_blocks(unit.get("excluded_blocks"), "%s.excluded_blocks" % base, errors)
    if isinstance(unit.get("selected_companion_blocks"), list) and isinstance(unit.get("excluded_blocks"), list):
        selected = unit["selected_companion_blocks"]
        for block_index, entry in enumerate(unit["excluded_blocks"]):
            if _is_object(entry) and collection_has(selected, get_prop(entry, "block")):
                errors.push("%s.excluded_blocks[%d].block: block is also selected" % (base, block_index))

    if not set_has(PRIOR_STATUSES, get_prop(unit, "prior_status")):
        errors.push("%s.prior_status: invalid value %s" % (base, safe_quote(get_prop(unit, "prior_status"))))
    if not set_has(STATUSES, get_prop(unit, "status")):
        errors.push("%s.status: invalid value %s" % (base, safe_quote(get_prop(unit, "status"))))
    wave = unit.get("wave")
    if not number_is_integer(wave) or wave < 1:
        errors.push("%s.wave: expected a positive integer" % base)
    agent_id = get_prop(unit, "agent_id")
    if agent_id is not None and not is_safe_agent_id(agent_id):
        errors.push("%s.agent_id: expected null or a safe agent ID" % base)

    validate_attempts(unit.get("attempts"), unit, base, errors)
    validate_string_array(unit.get("reviewed_paths"), "%s.reviewed_paths" % base, errors, path_value=True)
    validate_checks(unit.get("local_checks"), "%s.local_checks" % base, errors)
    validate_reviewed_path_ownership(unit, base, errors)
    validate_string_array(unit.get("result_fingerprints"), "%s.result_fingerprints" % base, errors, fingerprint=True)
    validate_string_array(unit.get("unresolved"), "%s.unresolved" % base, errors)

    validate_state_invariants(unit, base, errors)

    return errors


def validate_document(ledger):
    errors = create_error_list(VALIDATION_ERRORS)
    if not isinstance(ledger, list):
        errors.push("$: expected a top-level array")
        return errors
    if len(ledger) > MAX_UNITS:
        errors.push("$: exceeds %d coverage units" % MAX_UNITS)
        return errors

    errors.push(*preflight_document(ledger))
    if len(errors) > 0:
        return errors

    ids = {}
    semantics = {}
    previous_id = None
    for index in range(len(ledger)):
        if len(errors) >= VALIDATION_ERRORS:
            break
        unit = ledger[index]
        errors.push(*collect_unit_errors(unit, index))
        if len(errors) >= VALIDATION_ERRORS:
            break
        if not _is_object(unit) or not isinstance(unit.get("coverage_id"), str):
            continue

        key = semantic_key(unit) if has_valid_semantic_fields(unit) else None
        coverage_id = unit["coverage_id"]
        if coverage_id in ids:
            previous = ids[coverage_id]
            qualifier = (
                "canonical identity collision with different semantic fields"
                if key is not None and previous["key"] is not None and previous["key"] != key
                else "duplicate coverage ID"
            )
            errors.push("$[%d].coverage_id: %s at $[%d]" % (index, qualifier, previous["index"]))
        else:
            ids[coverage_id] = {"index": index, "key": key}
        if key is not None and key in semantics and semantics[key]["id"] != coverage_id:
            previous = semantics[key]
            errors.push("$[%d].canonical_refs: semantic tuple already uses coverage ID %s at $[%d]" % (index, safe_quote(previous["id"]), previous["index"]))
        elif key is not None:
            semantics[key] = {"id": coverage_id, "index": index}
        if previous_id is not None and previous_id > coverage_id:
            errors.push("$[%d].coverage_id: units must be sorted lexicographically" % index)
        previous_id = coverage_id
    return errors


def run(file):
    if not file:
        sys.stderr.write("Usage: python3 validate-coverage-ledger.py <path-to-coverage-ledger.json>\n")
        return 1

    try:
        contents = read_file_within_limit(file, MAX_INPUT_BYTES)
    except Exception as error:  # noqa: BLE001
        reason = str(error) if isinstance(error, SafeInputError) else "input could not be opened or read safely"
        sys.stderr.write("Failed to read coverage ledger: %s\n" % reason)
        return 1

    try:
        preflight_json_text(contents)
    except Exception as error:  # noqa: BLE001
        reason = str(error) if isinstance(error, JsonStructureError) else "invalid JSON structure"
        sys.stderr.write("Failed to parse coverage ledger: %s\n" % reason)
        return 1

    try:
        ledger = load_json_text(contents)
    except Exception:  # noqa: BLE001
        sys.stderr.write("Failed to parse coverage ledger: invalid JSON syntax\n")
        return 1

    try:
        errors = validate_document(ledger)
    except Exception:  # noqa: BLE001
        sys.stderr.write("Failed to validate coverage ledger: unexpected validation error\n")
        return 1

    for message in errors:
        sys.stderr.write("ERROR: %s\n" % escape_unsafe_diagnostic_characters(message))
    if len(errors) > 0:
        cap = "; output capped at %d" % VALIDATION_ERRORS if len(errors) == VALIDATION_ERRORS else ""
        sys.stderr.write("FAIL: %d validation error(s)%s\n" % (len(errors), cap))
        return 1
    sys.stdout.write("PASS: %d coverage units valid\n" % (len(ledger) if isinstance(ledger, list) else 0))
    return 0


def main():
    sys.exit(run(sys.argv[1] if len(sys.argv) > 1 else None))


if __name__ == "__main__":
    main()
