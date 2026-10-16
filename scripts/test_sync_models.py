#!/usr/bin/env python3
"""Conformance tests for scripts/sync-models.py.

Every case runs against a throwaway KIMI_CODE_HOME and a loopback HTTP server
that serves the gateway fixtures, so the real ~/.kimi-code is never touched.
The module under test is loaded by path, like skills/security-audit/test_validators.py.

Run either way:
  python3 scripts/test_sync_models.py
  python3 -m unittest discover -s scripts -p 'test_*.py'
"""

import contextlib
import difflib
import http.server
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import tomllib
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
PYTHON = sys.executable
SYNC = os.path.join(HERE, "sync-models.py")
PLAN_PATTERN = re.compile(r"plan:\s+sha256:([0-9a-f]{64})")


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, filename))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


sync = _load("sync_models_under_test", "sync-models.py")


# ---------------------------------------------------------------------------
# Gateway fixture
# ---------------------------------------------------------------------------

class GatewayFixture:
    def __init__(self):
        self.lock = threading.Lock()
        self.requests = []
        self.ids = []
        self.info = {}
        self.models_status = 200
        self.info_status = 200
        self.delay = 0.0
        self.raw_models = None
        self.bearer = None

    def models_body(self):
        if self.raw_models is not None:
            return self.raw_models
        return {"data": [{"id": name, "object": "model"} for name in self.ids]}

    def info_body(self):
        return {
            "data": [
                {"model_name": name, "model_info": dict(self.info[name])}
                for name in self.ids
                if name in self.info
            ]
        }


class _Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # keep the test output readable
        return

    def do_GET(self):
        fixture = self.server.fixture
        path = self.path.split("?")[0]
        with fixture.lock:
            fixture.requests.append((path, self.headers.get("Authorization")))
            authorized = fixture.bearer is None or self.headers.get("Authorization") == "Bearer " + fixture.bearer
            if not authorized:
                status, body, delay = 403, {"detail": "denied"}, fixture.delay
            elif path.endswith("/model/info"):
                status, body, delay = fixture.info_status, fixture.info_body(), fixture.delay
            else:
                status, body, delay = fixture.models_status, fixture.models_body(), fixture.delay
        if delay:
            time.sleep(delay)
        payload = json.dumps(body).encode("utf-8")
        if status != 200:
            payload = b'{"detail":"denied"}'
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        try:
            self.wfile.write(payload)
        except OSError:
            pass


class Gateway:
    """A loopback gateway serving /v1/models and /model/info."""

    def __init__(self):
        self.fixture = GatewayFixture()
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.server.fixture = self.fixture
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()

    @property
    def base_url(self):
        return "http://127.0.0.1:%d/v1" % self.server.server_address[1]

    def serve(self, ids, info=None, **options):
        self.fixture.ids = list(ids)
        self.fixture.info = dict(info or {})
        self.fixture.models_status = options.get("models_status", 200)
        self.fixture.info_status = options.get("info_status", 200)
        self.fixture.delay = options.get("delay", 0.0)
        self.fixture.raw_models = options.get("raw_models")
        self.fixture.bearer = options.get("bearer")


def model_info(
    max_input_tokens=200000,
    reasoning=None,
    vision=None,
    functions=None,
    efforts=None,
    default_effort=None,
    mode=None,
    display_name=None,
):
    record = {"max_input_tokens": max_input_tokens}
    if reasoning is not None:
        record["supports_reasoning"] = reasoning
    if vision is not None:
        record["supports_vision"] = vision
    if functions is not None:
        record["supports_function_calling"] = functions
    if efforts is not None:
        record["reasoning_effort_levels"] = list(efforts)
    if default_effort is not None:
        record["default_reasoning_effort"] = default_effort
    if mode is not None:
        record["mode"] = mode
    if display_name is not None:
        record["display_name"] = display_name
    return record


# ---------------------------------------------------------------------------
# Home fixtures
# ---------------------------------------------------------------------------

def block(
    alias,
    provider="litellm",
    model=None,
    context=200000,
    caps=("thinking",),
    efforts=("low", "medium", "high"),
    default=None,
    display=None,
):
    lines = [
        '[models."%s"]' % alias,
        'provider = "%s"' % provider,
        'model = "%s"' % (model if model is not None else alias.split("/", 1)[1]),
    ]
    if display is not None:
        lines.append('display_name = "%s"' % display)
    if context is not None:
        lines.append("max_context_size = %s" % context)
    if caps is not None:
        lines.append("capabilities = [ %s ]" % ", ".join('"%s"' % item for item in caps))
    if efforts is not None:
        lines.append("support_efforts = [ %s ]" % ", ".join('"%s"' % item for item in efforts))
    if default is not None:
        lines.append('default_effort = "%s"' % default)
    return "\n".join(lines)


def config_text(base_url, blocks=(), pool=None, providers=()):
    parts = [
        "[providers.litellm]",
        'type = "openai"',
        'base_url = "%s"' % base_url,
        'api_key = "sk-test-secret-value"',
        "",
    ]
    for name, body in providers:
        parts.append(body.rstrip("\n"))
        parts.append("")
    for item in blocks:
        parts.append(item)
        parts.append("")
    pool = pool if pool is not None else {'default_model': "litellm/glm-5.3", "models": ['"litellm/glm-5.3" = "Worker"']}
    parts.append("[secondary_model]")
    parts.append('default_model = "%s"' % pool["default_model"])
    parts.append("")
    parts.append("[secondary_model.models]")
    parts.extend(pool["models"])
    parts.append("")
    return "\n".join(parts)


FAMILIES_TEXT = """[families]
"Zeta"  = ["litellm/alpha", "litellm/old", "litellm/alpha"]
"Alpha" = ["litellm/beta"]
"Otro"  = ["other/thing"]
"""


class Home:
    def __init__(self, config, families=None, newline="\n", bom=False, raw_config=None):
        self.path = tempfile.mkdtemp(prefix="sync-models-test-")
        self.config = os.path.join(self.path, "config.toml")
        self.families = os.path.join(self.path, "kimi-swarm.toml")
        body = raw_config if raw_config is not None else config
        if bom:
            data = b"\xef\xbb\xbf" + body.replace("\n", newline).encode("utf-8")
        else:
            data = body.replace("\n", newline).encode("utf-8")
        with open(self.config, "wb") as handle:
            handle.write(data)
        if families is not None:
            with open(self.families, "wb") as handle:
                handle.write(families.replace("\n", newline).encode("utf-8"))

    def close(self):
        shutil.rmtree(self.path, ignore_errors=True)

    def read_config(self):
        with open(self.config, "rb") as handle:
            return handle.read()

    def config_document(self):
        return tomllib.loads(self.read_config().decode("utf-8").lstrip("\ufeff"))

    def read_families(self):
        with open(self.families, "rb") as handle:
            return handle.read()

    def families_document(self):
        return tomllib.loads(self.read_families().decode("utf-8").lstrip("\ufeff"))

    def snapshot(self):
        state = {}
        for name in sorted(os.listdir(self.path)):
            with open(os.path.join(self.path, name), "rb") as handle:
                state[name] = handle.read()
        return state


def run_sync(args):
    out = io.StringIO()
    err = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = sync.main(args)
    return code, out.getvalue(), err.getvalue()


def plan_of(output):
    match = PLAN_PATTERN.search(output)
    if match is None:
        raise AssertionError("no plan hash in output:\n%s" % output)
    return match.group(1)


def row_actions(output):
    """The action column of the plan table, one entry per row."""
    actions = []
    for line in output.splitlines():
        if " | " not in line or line.startswith("acción") or set(line) <= set("-+ "):
            continue
        actions.append(line.split(" | ", 1)[0].strip())
    return actions


def added_only(original, updated):
    """True when every diff line is an insertion (nothing removed or changed)."""
    diff = list(difflib.unified_diff(original.splitlines(True), updated.splitlines(True), n=0))
    return not any(line.startswith("-") and not line.startswith("---") for line in diff)


class SyncModelsTest(unittest.TestCase):
    maxDiff = None

    def setUp(self):
        self._homes = []

    def tearDown(self):
        for home in self._homes:
            home.close()

    def make_home(self, *args, **kwargs):
        home = Home(*args, **kwargs)
        self._homes.append(home)
        return home

    # 1 -------------------------------------------------------------------
    def test_new_alias_adds_only_its_block(self):
        with Gateway() as gateway:
            gateway.serve(
                ["alpha", "beta"],
                {
                    "alpha": model_info(efforts=["low", "medium"]),
                    "beta": model_info(efforts=["low", "high"], vision=True, reasoning=True),
                },
            )
            home = self.make_home(
                config_text(gateway.base_url, [block("litellm/alpha", caps=("thinking",), efforts=("low", "medium"))])
            )
            original = home.read_config()
            code, output, _err = run_sync(["--home", home.path])
            self.assertEqual(code, 0, output)
            self.assertIn("alta", output)
            applied, output, _err = run_sync(["--home", home.path, "--apply", "--expect-plan", plan_of(output)])
            self.assertEqual(applied, 0, output)
            updated = home.read_config()
            self.assertNotEqual(updated, original)
            self.assertTrue(added_only(original.decode(), updated.decode()), "something other than the new block changed")
            document = home.config_document()
            self.assertEqual(
                document["models"]["litellm/beta"],
                {
                    "provider": "litellm",
                    "model": "beta",
                    "max_context_size": 200000,
                    "capabilities": ["image_in", "thinking"],
                    "support_efforts": ["low", "high"],
                },
            )
            self.assertEqual(document["models"]["litellm/alpha"], tomllib.loads(original.decode())["models"]["litellm/alpha"])

    # 2 -------------------------------------------------------------------
    def test_dry_run_writes_nothing(self):
        with Gateway() as gateway:
            gateway.serve(["alpha", "beta"], {"beta": model_info()})
            home = self.make_home(config_text(gateway.base_url, [block("litellm/alpha")]))
            before = home.snapshot()
            code, output, _err = run_sync(["--home", home.path])
            self.assertEqual(code, 0, output)
            self.assertIn("beta", output)
            self.assertEqual(home.snapshot(), before, "the dry run touched the home directory")

    # 3 -------------------------------------------------------------------
    def test_second_apply_is_idempotent(self):
        with Gateway() as gateway:
            gateway.serve(["alpha", "beta"], {"beta": model_info()})
            home = self.make_home(config_text(gateway.base_url, [block("litellm/alpha")]))
            _code, output, _err = run_sync(["--home", home.path])
            first, output, _err = run_sync(["--home", home.path, "--apply", "--expect-plan", plan_of(output)])
            self.assertEqual(first, 0, output)
            applied = home.read_config()
            second, output, _err = run_sync(["--home", home.path])
            self.assertEqual(second, 0, output)
            self.assertIn("sin cambios", output)
            third, output, _err = run_sync(["--home", home.path, "--apply", "--expect-plan", plan_of(output)])
            self.assertEqual(third, 0, output)
            self.assertIn("nada para escribir", output)
            self.assertEqual(home.read_config(), applied, "the second apply changed the file")

    # 4 -------------------------------------------------------------------
    def test_existing_values_are_kept_and_contradictions_are_informative(self):
        with Gateway() as gateway:
            gateway.serve(
                ["alpha"],
                {"alpha": model_info(max_input_tokens=100000, functions=False, efforts=["low", "medium"])},
            )
            home = self.make_home(
                config_text(
                    gateway.base_url,
                    [block("litellm/alpha", context=200000, caps=("thinking", "tool_use"), efforts=("low", "medium", "high"))],
                )
            )
            original = home.read_config()
            code, output, _err = run_sync(["--home", home.path, "--refresh-metadata"])
            self.assertEqual(code, 0, output)
            self.assertIn("contradicción", output)
            self.assertIn("informative", output)
            applied, output, _err = run_sync(
                ["--home", home.path, "--refresh-metadata", "--apply", "--expect-plan", plan_of(output)]
            )
            self.assertEqual(applied, 0, output)
            self.assertEqual(home.read_config(), original, "a present value was rewritten")
            self.assertEqual(home.config_document()["models"]["litellm/alpha"]["capabilities"], ["thinking", "tool_use"])

    # 5 -------------------------------------------------------------------
    def test_capabilities_union_never_removes(self):
        with Gateway() as gateway:
            gateway.serve(["alpha"], {"alpha": model_info(vision=True)})
            home = self.make_home(
                config_text(gateway.base_url, [block("litellm/alpha", caps=("thinking", "tool_use"))])
            )
            _code, output, _err = run_sync(["--home", home.path, "--refresh-metadata"])
            code, output, _err = run_sync(
                ["--home", home.path, "--refresh-metadata", "--apply", "--expect-plan", plan_of(output)]
            )
            self.assertEqual(code, 0, output)
            self.assertEqual(
                home.config_document()["models"]["litellm/alpha"]["capabilities"],
                ["thinking", "tool_use", "image_in"],
            )
            self.assertIn(
                'capabilities = [ "thinking", "tool_use", "image_in" ]\n'
                'support_efforts = [ "low", "medium", "high" ]\n',
                home.read_config().decode(),
                "rewriting a field changed the lines around it",
            )

    # 6 -------------------------------------------------------------------
    def test_support_efforts_union_keeps_local_max(self):
        with Gateway() as gateway:
            gateway.serve(["alpha"], {"alpha": model_info(efforts=["low", "medium", "high"])})
            home = self.make_home(
                config_text(gateway.base_url, [block("litellm/alpha", efforts=("low", "medium", "max"))])
            )
            _code, output, _err = run_sync(["--home", home.path, "--refresh-metadata"])
            code, output, _err = run_sync(
                ["--home", home.path, "--refresh-metadata", "--apply", "--expect-plan", plan_of(output)]
            )
            self.assertEqual(code, 0, output)
            self.assertEqual(
                home.config_document()["models"]["litellm/alpha"]["support_efforts"],
                ["low", "medium", "max", "high"],
            )
            self.assertIn(
                'support_efforts = [ "low", "medium", "max", "high" ]\n',
                home.read_config().decode(),
            )
            self.assertEqual(home.read_config().decode().count("\n\n\n"), 0, "a blank line was inserted")

    # 7 -------------------------------------------------------------------
    def test_variant_groups_and_the_invariant(self):
        with Gateway() as gateway:
            gateway.serve(
                ["base", "safe"],
                {
                    "base": model_info(efforts=["low", "medium", "high"]),
                    "safe": model_info(efforts=["low", "high", "max"]),
                },
            )
            home = self.make_home(
                config_text(
                    gateway.base_url,
                    [
                        block("litellm/base", efforts=("low", "medium")),
                        block("litellm/base@max", model="base", efforts=("low", "medium", "max"), default="max"),
                        block("litellm/safe", efforts=("low", "high")),
                        block("litellm/safe@high", model="safe", efforts=("low", "high"), default="high"),
                    ],
                )
            )
            original = home.config_document()
            code, output, _err = run_sync(["--home", home.path, "--refresh-metadata"])
            self.assertEqual(code, 1, output)
            self.assertIn("omitido", output)
            self.assertIn("invariante", output)
            applied, output, _err = run_sync(
                ["--home", home.path, "--refresh-metadata", "--apply", "--expect-plan", plan_of(output)]
            )
            self.assertEqual(applied, 1, output)
            document = home.config_document()
            self.assertEqual(
                document["models"]["litellm/base"]["support_efforts"],
                original["models"]["litellm/base"]["support_efforts"],
                "the broken group still changed",
            )
            self.assertEqual(
                document["models"]["litellm/base@max"]["support_efforts"],
                original["models"]["litellm/base@max"]["support_efforts"],
            )
            self.assertEqual(document["models"]["litellm/base@max"]["default_effort"], "max")
            self.assertEqual(document["models"]["litellm/safe"]["support_efforts"], ["low", "high", "max"])
            self.assertEqual(document["models"]["litellm/safe@high"]["support_efforts"], ["low", "high", "max"])
            self.assertEqual(document["models"]["litellm/safe@high"]["default_effort"], "high")

    # 8 -------------------------------------------------------------------
    def test_provider_key_and_pool_are_untouched(self):
        with Gateway() as gateway:
            gateway.serve(["alpha", "beta"], {"beta": model_info()})
            home = self.make_home(config_text(gateway.base_url, [block("litellm/alpha")]))
            original = home.config_document()
            _code, output, _err = run_sync(["--home", home.path])
            code, output, _err = run_sync(["--home", home.path, "--apply", "--expect-plan", plan_of(output)])
            self.assertEqual(code, 0, output)
            document = home.config_document()
            self.assertEqual(document["providers"]["litellm"]["api_key"], original["providers"]["litellm"]["api_key"])
            self.assertEqual(document["secondary_model"], original["secondary_model"])
            raw = home.read_config().decode()
            self.assertNotIn("sk-test-secret-value", output.replace('api_key = "sk-test-secret-value"', ""))
            self.assertEqual(raw.count("sk-test-secret-value"), 1)

    # 9 -------------------------------------------------------------------
    def test_model_info_forbidden_is_partial_without_additions(self):
        with Gateway() as gateway:
            gateway.serve(["alpha", "beta"], {"beta": model_info()}, info_status=403)
            home = self.make_home(config_text(gateway.base_url, [block("litellm/alpha")]))
            before = home.snapshot()
            code, output, _err = run_sync(["--home", home.path, "--refresh-metadata"])
            self.assertEqual(code, 1, output)
            self.assertIn("metadata", output)
            self.assertNotIn("| alta ", output)
            self.assertEqual(home.snapshot(), before, "a partial run wrote something")

    # 10 ------------------------------------------------------------------
    def test_unreachable_and_empty_catalog_exit_four(self):
        with Gateway() as gateway:
            gateway.serve(["alpha"], {"alpha": model_info()}, delay=5.0)
            home = self.make_home(config_text(gateway.base_url, [block("litellm/alpha")]))
            original_timeout = sync.REQUEST_TIMEOUT
            sync.REQUEST_TIMEOUT = 0.3
            try:
                before = home.snapshot()
                code, output, err = run_sync(["--home", home.path])
            finally:
                sync.REQUEST_TIMEOUT = original_timeout
            self.assertEqual(code, 4, output + err)
            self.assertEqual(home.snapshot(), before)

            gateway.serve([], raw_models={"data": []})
            code, output, err = run_sync(["--home", home.path])
            self.assertEqual(code, 4, output + err)
            self.assertEqual(home.snapshot(), before)

    # 11 ------------------------------------------------------------------
    def test_mode_blacklist_keeps_null_and_drops_non_chat(self):
        with Gateway() as gateway:
            gateway.serve(
                ["plain", "picture", "embed"],
                {
                    "plain": model_info(mode=None),
                    "picture": model_info(mode="image_generation"),
                    "embed": model_info(mode="embedding"),
                },
            )
            home = self.make_home(config_text(gateway.base_url, []))
            code, output, _err = run_sync(["--home", home.path])
            self.assertEqual(code, 0, output)
            self.assertIn("exclusión", output)
            self.assertEqual(row_actions(output).count("exclusión"), 2)
            applied, output, _err = run_sync(["--home", home.path, "--apply", "--expect-plan", plan_of(output)])
            self.assertEqual(applied, 0, output)
            models = home.config_document()["models"]
            self.assertIn("litellm/plain", models)
            self.assertNotIn("litellm/picture", models)
            self.assertNotIn("litellm/embed", models)

    # 12 ------------------------------------------------------------------
    def test_malicious_model_id_is_refused_escaped_and_inert(self):
        hostile = 'x"]\n[secondary_model]\ndefault_model = "attacker'
        with Gateway() as gateway:
            gateway.serve([hostile, "alpha"], {"alpha": model_info()})
            home = self.make_home(config_text(gateway.base_url, []))
            before = home.snapshot()
            code, output, err = run_sync(["--home", home.path])
            self.assertEqual(code, 1, output + err)
            self.assertIn("rechazo", output)
            self.assertIn("\\u000a", output)
            self.assertNotIn('[secondary_model]\ndefault_model = "attacker', output)
            self.assertEqual(home.snapshot(), before)
            applied, output, _err = run_sync(["--home", home.path, "--apply", "--expect-plan", plan_of(output)])
            self.assertEqual(applied, 1, output)
            self.assertNotIn(b"attacker", home.read_config(), "the hostile id reached the file")
            document = home.config_document()
            self.assertEqual(document["secondary_model"]["default_model"], "litellm/glm-5.3")
            self.assertEqual(sorted(document["models"]), ["litellm/alpha"])

    # 13 ------------------------------------------------------------------
    def test_broken_toml_exits_three(self):
        with Gateway() as gateway:
            gateway.serve(["alpha"], {"alpha": model_info()})
            home = self.make_home("", raw_config='[providers.litellm\nbase_url = "x"\n')
            before = home.snapshot()
            code, output, err = run_sync(["--home", home.path])
            self.assertEqual(code, 3, output + err)
            self.assertEqual(home.snapshot(), before)

    # 14 ------------------------------------------------------------------
    def test_lock_held_and_stale_plan_exit_five(self):
        with Gateway() as gateway:
            gateway.serve(["alpha", "beta"], {"beta": model_info()})
            home = self.make_home(config_text(gateway.base_url, [block("litellm/alpha")]))
            _code, output, _err = run_sync(["--home", home.path])
            digest = plan_of(output)

            lock_path = os.path.join(home.path, sync.LOCK_NAME)
            handle = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
            import fcntl

            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            try:
                before = home.snapshot()
                code, output, err = run_sync(["--home", home.path, "--apply", "--expect-plan", digest])
                self.assertEqual(code, 5, output + err)
                self.assertEqual(home.snapshot(), before, "a locked run wrote something")
            finally:
                fcntl.flock(handle, fcntl.LOCK_UN)
                os.close(handle)

            with open(home.config, "a", encoding="utf-8") as stream:
                stream.write("# concurrent edit\n")
            after_edit = home.read_config()
            code, output, err = run_sync(["--home", home.path, "--apply", "--expect-plan", digest])
            self.assertEqual(code, 5, output + err)
            self.assertEqual(home.read_config(), after_edit, "a stale plan overwrote a concurrent change")

    # 15 ------------------------------------------------------------------
    def test_refresh_families_preserves_order_and_duplicates(self):
        with Gateway() as gateway:
            gateway.serve(
                ["alpha", "beta", "gamma"],
                {"alpha": model_info(), "beta": model_info(), "gamma": model_info()},
            )
            home = self.make_home(
                config_text(gateway.base_url, [block("litellm/alpha"), block("litellm/old")]),
                families=FAMILIES_TEXT,
            )
            original = home.read_families()
            code, output, _err = run_sync(["--home", home.path, "--refresh-families"])
            self.assertEqual(code, 1, output)
            self.assertIn("retirar", output)
            self.assertIn("agregar", output)
            self.assertIn("[secondary_model.models]", output)
            applied, output, _err = run_sync(
                ["--home", home.path, "--refresh-families", "--apply", "--expect-plan", plan_of(output)]
            )
            self.assertEqual(applied, 1, output)
            updated = home.read_families()
            self.assertNotEqual(updated, original)
            self.assertNotIn("litellm/old", updated.decode())
            self.assertEqual(
                home.families_document()["families"],
                {
                    "Zeta": ["litellm/alpha", "litellm/alpha"],
                    "Alpha": ["litellm/beta"],
                    "Otro": ["other/thing"],
                    "Sin clasificar": ["litellm/gamma"],
                },
            )
            self.assertEqual(list(home.families_document()["families"]), ["Zeta", "Alpha", "Otro", "Sin clasificar"])

    # 16 ------------------------------------------------------------------
    def test_bom_and_crlf_survive(self):
        with Gateway() as gateway:
            gateway.serve(["alpha", "beta"], {"beta": model_info()})
            home = self.make_home(
                config_text(gateway.base_url, [block("litellm/alpha")]),
                newline="\r\n",
                bom=True,
            )
            _code, output, _err = run_sync(["--home", home.path])
            code, output, _err = run_sync(["--home", home.path, "--apply", "--expect-plan", plan_of(output)])
            self.assertEqual(code, 0, output)
            raw = home.read_config()
            self.assertTrue(raw.startswith(b"\xef\xbb\xbf"), "the BOM was dropped")
            self.assertNotRegex(raw.decode("utf-8")[1:], r"(?<!\r)\n")
            self.assertIn("litellm/beta", home.config_document()["models"])

    # extra ---------------------------------------------------------------
    def test_api_key_env_is_read_and_a_missing_one_degrades(self):
        env_name = "SYNC_MODELS_TEST_KEY"
        config = (
            "[providers.litellm]\n"
            'type = "openai"\n'
            "base_url = \"%s\"\n"
            'api_key_env = "%s"\n'
        )
        with Gateway() as gateway:
            gateway.serve(["alpha"], {"alpha": model_info()}, bearer="env-secret")
            home = self.make_home(config % (gateway.base_url, env_name))
            saved = os.environ.pop(env_name, None)
            try:
                before = home.snapshot()
                code, output, err = run_sync(["--home", home.path])
                self.assertEqual(code, 4, output + err)
                self.assertNotIn("env-secret", output + err)
                self.assertEqual(home.snapshot(), before)

                os.environ[env_name] = "env-secret"
                code, output, _err = run_sync(["--home", home.path])
                self.assertEqual(code, 0, output)
                self.assertEqual(
                    [entry for entry in gateway.fixture.requests if "models" in entry[0]][-1][1],
                    "Bearer env-secret",
                )
                self.assertNotIn("env-secret", output)
            finally:
                os.environ.pop(env_name, None)
                if saved is not None:
                    os.environ[env_name] = saved

    def test_cli_entry_point_runs_as_a_subprocess(self):
        with Gateway() as gateway:
            gateway.serve(["alpha", "beta"], {"beta": model_info()})
            home = self.make_home(config_text(gateway.base_url, [block("litellm/alpha")]))
            completed = subprocess.run(
                [PYTHON, SYNC, "--home", home.path],
                capture_output=True,
                timeout=30,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr.decode())
            self.assertIn("provider:  litellm", completed.stdout.decode())
            self.assertIn("plan:      sha256:", completed.stdout.decode())


if __name__ == "__main__":
    unittest.main(verbosity=2)
