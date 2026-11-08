"""Streamable HTTP transport: --url, --header, --header-env, secrecy and validation."""

import contextlib
import io
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest import mock

from mcp_lint.cli import main
from mcp_lint.client import (
    HttpConfigError, HttpTarget, describe_http_error, is_loopback_host, parse_headers, redact,
    validate_url,
)

try:
    _ExceptionGroup = ExceptionGroup
except NameError:  # Python 3.10: anyio depends on the backport there
    from exceptiongroup import ExceptionGroup as _ExceptionGroup

HERE = os.path.dirname(__file__)
DEMO_SERVER = os.path.join(HERE, "fixtures", "demo_server.py")


def run_cli(*argv, env=None):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        with mock.patch.dict(os.environ, env or {}):
            code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


def run_cli_stdio(*argv):
    """Like run_cli, but leaves stderr alone: stdio_client needs a real file for the server's stderr."""
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = main(list(argv))
    return code, out.getvalue(), ""


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_listening(port, timeout=30.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.2)
    return False


class HttpTestCase(unittest.TestCase):
    def start_demo(self, *extra):
        port = free_port()
        proc = subprocess.Popen([sys.executable, DEMO_SERVER, "--http", str(port), *extra],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        def stop():
            proc.kill()  # only this Popen handle
            proc.wait(timeout=10)

        self.addCleanup(stop)
        self.assertTrue(wait_listening(port), "demo HTTP server did not start")
        return f"http://127.0.0.1:{port}/mcp", port

    def tmp(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        return d.name


class RunOverHttpTests(HttpTestCase):
    def test_lists_tools_and_matches_stdio_exit_code(self):
        url, _ = self.start_demo()
        code, out, _ = run_cli("run", "--url", url)
        stdio_code, _, _ = run_cli_stdio("run", "--", sys.executable, DEMO_SERVER)
        self.assertIn("search_contacts", out)
        self.assertIn("get", out)
        self.assertEqual(code, stdio_code)

    def test_error_probes(self):
        url, _ = self.start_demo()
        code, out, _ = run_cli("run", "--url", url, "--error-probes")
        self.assertIn("search_contacts", out)
        self.assertIn("probe", out.lower())
        self.assertIn("Probes", out)
        self.assertIn("auto: missing query", out)

    def test_benign_literal_header(self):
        url, _ = self.start_demo()
        code, out, _ = run_cli("run", "--url", url, "--header", "X-Client: mcp-lint")
        stdio_code, _, _ = run_cli_stdio("run", "--", sys.executable, DEMO_SERVER)
        self.assertIn("search_contacts", out)
        self.assertEqual(code, stdio_code)

    def test_json_has_transport_and_no_url(self):
        url, port = self.start_demo()
        path = os.path.join(self.tmp(), "r.json")
        run_cli("run", "--url", url, "--json", path)
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        server = json.loads(text)["server"]
        self.assertEqual(server["transport"], "streamable-http")
        self.assertTrue(server["command_sha256"].startswith("sha256:"))
        self.assertNotIn(f"127.0.0.1:{port}", text)
        _, _, _ = run_cli_stdio("run", "--json", path, "--", sys.executable, DEMO_SERVER)
        with open(path, encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)["server"]["transport"], "stdio")

    def test_init_fixtures(self):
        url, _ = self.start_demo()
        out_path = os.path.join(self.tmp(), "fx.json")
        code, _, _ = run_cli("init-fixtures", out_path, "--url", url)
        self.assertEqual(code, 0)
        with open(out_path, encoding="utf-8") as fh:
            text = fh.read()
        self.assertIn("search_contacts", text)
        self.assertIn('"get"', text)


class LockOverHttpTests(HttpTestCase):
    def test_lock_and_check(self):
        url, port = self.start_demo()
        d = self.tmp()
        lock = os.path.join(d, "http.lock")
        code, _, _ = run_cli("lock", "--url", url, "--header", "X-Client: HDRVAL-1", "--lock", lock)
        self.assertEqual(code, 0)
        code, _, _ = run_cli("lock", "--check", "--url", url, "--lock", lock)
        self.assertEqual(code, 0)
        with open(lock, encoding="utf-8") as fh:
            text = fh.read()
        self.assertNotIn(f"127.0.0.1:{port}", text)
        self.assertNotIn("HDRVAL-1", text)
        stdio_lock = os.path.join(d, "stdio.lock")
        self.assertEqual(run_cli_stdio("lock", "--lock", stdio_lock, "--", sys.executable, DEMO_SERVER)[0], 0)
        with open(stdio_lock, encoding="utf-8") as fh:
            stdio_text = fh.read()
        self.assertNotEqual(json.loads(text)["server"]["command_sha256"],
                            json.loads(stdio_text)["server"]["command_sha256"])

    def test_token_rotation_does_not_change_lock(self):
        url, _ = self.start_demo()
        lock = os.path.join(self.tmp(), "r.lock")
        self.assertEqual(run_cli("lock", "--url", url, "--header", "X-Client: old", "--lock", lock)[0], 0)
        code, _, _ = run_cli("lock", "--check", "--url", url, "--header", "X-Client: new",
                             "--lock", lock)
        self.assertEqual(code, 0)

    def test_query_token_is_not_hashed(self):
        # The hash covers scheme, host, port and path only: rotating a ?token= isn't a
        # change, and the committed lock can't be used to guess the token.
        from mcp_lint.lock import command_hash

        url, _ = self.start_demo()
        lock = os.path.join(self.tmp(), "q.lock")
        self.assertEqual(run_cli("lock", "--url", url + "?token=QTOKEN-OLD", "--lock", lock)[0], 0)
        code, out, _ = run_cli("lock", "--check", "--url", url + "?token=QTOKEN-NEW", "--lock", lock)
        self.assertEqual(code, 0)
        self.assertNotIn("launch command changed", out)
        with open(lock, encoding="utf-8") as fh:
            stored = json.load(fh)["server"]["command_sha256"]
        self.assertEqual(stored, command_hash(["--url", url]))
        self.assertNotEqual(stored, command_hash(["--url", url + "?token=QTOKEN-OLD"]))


class AuthTests(HttpTestCase):
    SECRET = "s3cr3t-HDR"

    def test_header_env_authenticates_and_never_leaks(self):
        url, _ = self.start_demo("--require-header", f"X-Api-Key={self.SECRET}")
        path = os.path.join(self.tmp(), "r.json")
        code, out, err = run_cli("run", "--url", url, "--header-env", "X-Api-Key=MY_KEY",
                                 "--json", path, "--error-probes", env={"MY_KEY": self.SECRET})
        self.assertIn("search_contacts", out)
        self.assertNotEqual(code, 2)
        with open(path, encoding="utf-8") as fh:
            blob = out + err + fh.read()
        self.assertNotIn(self.SECRET, blob)

    def test_missing_header_is_refused(self):
        url, _ = self.start_demo("--require-header", f"X-Api-Key={self.SECRET}")
        path = os.path.join(self.tmp(), "r.json")
        code, out, err = run_cli("run", "--url", url, "--json", path, env={"MY_KEY": self.SECRET})
        self.assertEqual(code, 2)
        self.assertIn("could not connect to http://127.0.0.1", err)
        self.assertFalse(os.path.exists(path))
        self.assertNotIn(self.SECRET, out + err)

    def test_wrong_header_value_is_refused_without_leak(self):
        url, _ = self.start_demo("--require-header", f"X-Api-Key={self.SECRET}")
        code, out, err = run_cli("run", "--url", url, "--header-env", "X-Api-Key=MY_KEY",
                                 env={"MY_KEY": "WRONGVALUE-42"})
        self.assertEqual(code, 2)
        self.assertNotIn("WRONGVALUE-42", out + err)


class ConnectionFailureTests(HttpTestCase):
    def test_closed_port_redacts_query_and_header(self):
        port = free_port()  # nothing listens here
        url = f"http://127.0.0.1:{port}/mcp?token=QUERYSECRET"
        code, out, err = run_cli("run", "--url", url, "--header-env", "X-K=V", env={"V": "HDRSECRET"})
        self.assertEqual(code, 2)
        for text in (out, err):
            self.assertNotIn("QUERYSECRET", text)
            self.assertNotIn("HDRSECRET", text)
        self.assertIn("http://127.0.0.1", err)

    def test_userinfo_redacted(self):
        port = free_port()
        url = f"http://user:PASSSECRET@127.0.0.1:{port}/mcp"
        code, out, err = run_cli("lock", "--url", url, "--lock", os.path.join(self.tmp(), "x.lock"))
        self.assertEqual(code, 2)
        self.assertNotIn("PASSSECRET", out + err)


class UsageErrorTests(unittest.TestCase):
    def assert_usage(self, *argv, mention=None, env=None):
        names = ("fetch_tools_http", "fetch_and_probe_http", "fetch_tools")
        with contextlib.ExitStack() as stack:
            mocks = [stack.enter_context(mock.patch(f"mcp_lint.client.{n}")) for n in names]
            code, out, err = run_cli(*argv, env=env)
        for m in mocks:
            m.assert_not_called()  # the exit code alone would also match a swallowed connect failure
        self.assertEqual(code, 2, (out, err))
        if mention:
            self.assertIn(mention, err)
        return err

    def test_refuses_secret_over_plain_http(self):
        err = self.assert_usage("run", "--url", "http://example.invalid/mcp",
                                "--header-env", "X-K=V", env={"V": "SECRETVAL"})
        self.assertIn("unencrypted", err)
        self.assertNotIn("SECRETVAL", err)

    def test_url_and_command(self):
        self.assert_usage("run", "--url", "http://127.0.0.1:1/mcp", "--", "python", "x.py")

    def test_url_and_pass_env(self):
        self.assert_usage("run", "--url", "http://127.0.0.1:1/mcp", "--pass-env", "FOO")

    def test_header_without_url(self):
        self.assert_usage("run", "--header", "X-A: b", "--", "python", "x.py")
        self.assert_usage("run", "--header-env", "X-A=B", "--", "python", "x.py")

    def test_bad_scheme(self):
        self.assert_usage("run", "--url", "ftp://h/x")

    def test_no_host(self):
        self.assert_usage("run", "--url", "http:///x")

    def test_bad_header_name(self):
        self.assert_usage("run", "--url", "http://127.0.0.1:1/mcp", "--header", "Bad Name: v")

    def test_header_newline(self):
        self.assert_usage("run", "--url", "http://127.0.0.1:1/mcp", "--header", "X-A: b\r\nX-B: c")

    def test_header_no_colon(self):
        self.assert_usage("run", "--url", "http://127.0.0.1:1/mcp", "--header", "nocolon")

    def test_unset_env_var(self):
        with mock.patch.dict(os.environ):
            os.environ.pop("UNSET_VAR_123", None)
            self.assert_usage("run", "--url", "http://127.0.0.1:1/mcp",
                              "--header-env", "X-K=UNSET_VAR_123", mention="UNSET_VAR_123")

    def test_duplicate_header(self):
        self.assert_usage("run", "--url", "http://127.0.0.1:1/mcp",
                          "--header", "X-A: 1", "--header", "x-a: 2")

    def test_lock_url_with_from(self):
        self.assert_usage("lock", "--url", "http://127.0.0.1:1/mcp", "--from", "file.json")

    def test_init_fixtures_url_with_from(self):
        self.assert_usage("init-fixtures", "out.json", "--url", "http://127.0.0.1:1/mcp",
                          "--from", "file.json")

    def test_proxy_has_no_url(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            main(["proxy", "--url", "http://127.0.0.1:1/mcp"])


class HelperTests(unittest.TestCase):
    def test_loopback_predicate(self):
        for host in ("localhost", "127.0.0.1", "127.0.0.5", "::1", "[::1]", "LOCALHOST"):
            self.assertTrue(is_loopback_host(host), host)
        for host in ("example.com", "10.0.0.1", "192.168.1.1", "0.0.0.0", "", None):
            self.assertFalse(is_loopback_host(host), host)

    def test_loopback_http_allows_secret_headers(self):
        env = {"V": "x"}
        for url in ("http://localhost:9/mcp", "http://127.0.0.5:9/mcp", "http://[::1]:9/mcp"):
            self.assertEqual(parse_headers(url, [], ["X-K=V"], env), {"X-K": "x"})

    def test_https_passes_validation(self):
        self.assertEqual(parse_headers("https://example.invalid/mcp", [], ["X-K=V"], {"V": "x"}),
                         {"X-K": "x"})

    def test_plain_http_remote_literal_header_allowed(self):
        self.assertEqual(parse_headers("http://example.invalid/mcp", ["X-A: b"]), {"X-A": "b"})

    def test_plain_http_remote_env_header_refused(self):
        with self.assertRaises(HttpConfigError):
            parse_headers("http://example.invalid/mcp", [], ["X-K=V"], {"V": "x"})

    def test_env_value_with_newline_rejected(self):
        with self.assertRaises(HttpConfigError) as cm:
            parse_headers("https://h/mcp", [], ["X-K=V"], {"V": "a\nb"})
        self.assertNotIn("a\nb", str(cm.exception))

    def test_validate_url(self):
        validate_url("https://h/mcp")
        for bad in ("ftp://h/x", "http:///x", "h/mcp", "http://h:notaport/x"):
            with self.assertRaises(HttpConfigError, msg=bad):
                validate_url(bad)

    def test_redact(self):
        url = "https://user:pw0rd@h.example/mcp?token=TOKENX"
        text = f"failed for {url}; query token=TOKENX; hdr HVALUE; user pw0rd"
        out = redact(text, url, {"Authorization": "HVALUE"})
        for s in ("pw0rd", "TOKENX", "HVALUE", "user:pw0rd"):
            self.assertNotIn(s, out)
        self.assertIn("[redacted]", out)

    def test_describe_unwraps_exception_group(self):
        target = HttpTarget("https://h.example/mcp?token=TOKENX", {"A": "HVALUE"})
        group = _ExceptionGroup("g", [ValueError("bad TOKENX and HVALUE"), KeyError("x")])
        msg = describe_http_error(group, target)
        self.assertTrue(msg.startswith("could not connect to https://h.example: ValueError: "))
        self.assertNotIn("TOKENX", msg)
        self.assertNotIn("HVALUE", msg)

    def test_target_repr_hides_secrets(self):
        target = HttpTarget("https://h.example/mcp?token=TOKENX", {"A": "HVALUE"})
        self.assertNotIn("TOKENX", repr(target))
        self.assertNotIn("HVALUE", repr(target))


class RedirectTests(unittest.TestCase):
    def test_cross_origin_redirect_does_not_forward_header(self):
        seen = []

        class Recorder(BaseHTTPRequestHandler):
            def _record(self):
                seen.append({k: v for k, v in self.headers.items()})
                self.send_response(500)
                self.send_header("Content-Length", "0")
                self.end_headers()

            do_GET = do_POST = do_DELETE = _record

            def log_message(self, *a):
                pass

        b = HTTPServer(("127.0.0.1", 0), Recorder)
        b_port = b.server_address[1]

        class Redirector(BaseHTTPRequestHandler):
            def _redir(self):
                self.send_response(307)
                self.send_header("Location", f"http://127.0.0.1:{b_port}/mcp")
                self.send_header("Content-Length", "0")
                self.end_headers()

            do_GET = do_POST = do_DELETE = _redir

            def log_message(self, *a):
                pass

        a = HTTPServer(("127.0.0.1", 0), Redirector)
        a_port = a.server_address[1]
        for srv in (a, b):
            t = threading.Thread(target=srv.serve_forever, daemon=True)
            t.start()
            self.addCleanup(srv.server_close)
            self.addCleanup(srv.shutdown)

        code, out, err = run_cli("run", "--url", f"http://127.0.0.1:{a_port}/mcp",
                                 "--header-env", "X-Secret=VAR", env={"VAR": "REDIRSECRET"})
        self.assertEqual(code, 2)
        self.assertNotIn("REDIRSECRET", json.dumps(seen))
        self.assertNotIn("REDIRSECRET", out + err)


class StubServer:
    """Plain-JSON Streamable HTTP stub that can echo the X-K request header back."""

    def __init__(self, testcase):
        self.echo_definitions = False  # put the header value in the server name and tool description
        self.echo_errors = True  # put the header value in tools/call errors
        self.description_suffix = ""  # extra text for the tool description
        self.error_prefix = ""  # text before the echoed key in tools/call errors
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, status, body=None):
                data = b"" if body is None else json.dumps(body).encode()
                self.send_response(status)
                if body is not None:
                    self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                self._send(405)

            def do_DELETE(self):
                self._send(405)

            def do_POST(self):
                msg = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
                key = self.headers.get("X-K", "")
                method, mid = msg.get("method"), msg.get("id")
                if mid is None:
                    return self._send(202)
                if method == "initialize":
                    name = "stub-server" + (f" {key}" if stub.echo_definitions else "")
                    result = {"protocolVersion": msg["params"]["protocolVersion"],
                              "capabilities": {"tools": {}},
                              "serverInfo": {"name": name, "version": "1"}}
                elif method == "tools/list":
                    desc = "Looks up a thing by query and returns the best matches, with limits."
                    if stub.echo_definitions:
                        desc += f" key={key}"
                    desc += stub.description_suffix
                    result = {"tools": [{
                        "name": "lookup", "description": desc,
                        "inputSchema": {"type": "object", "required": ["query"],
                                        "properties": {"query": {"type": "string",
                                                                 "description": "Text to look up."}}},
                        "annotations": {"readOnlyHint": True}}]}
                elif method == "tools/call":
                    text = (f"{stub.error_prefix}bad request, your key {key} lacks scope"
                            if stub.echo_errors else "bad request")
                    return self._send(200, {"jsonrpc": "2.0", "id": mid,
                                            "error": {"code": -32602, "message": text}})
                else:
                    result = {}
                self._send(200, {"jsonrpc": "2.0", "id": mid, "result": result})

        self.httpd = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}/mcp"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        testcase.addCleanup(self.httpd.server_close)
        testcase.addCleanup(self.httpd.shutdown)


class EchoedSecretTests(HttpTestCase):
    SECRET = "ECHOSECRET"

    def test_run_redacts_echoed_secret_everywhere(self):
        stub = StubServer(self)
        path = os.path.join(self.tmp(), "r.json")
        for flags in ((), ("--include-responses",)):
            code, out, err = run_cli("run", "--url", stub.url, "--header-env", "X-K=V", "--error-probes",
                                     "--json", path, *flags, env={"V": self.SECRET})
            with open(path, encoding="utf-8") as fh:
                blob = fh.read()
            self.assertIn("auto: missing query", out)
            self.assertIn("[redacted]", out)
            self.assertNotIn(self.SECRET, out + err + blob)
            json.loads(blob)  # still valid JSON

    def test_run_redacts_secret_cut_by_truncation(self):
        # Rules quote the first 90 (or 40) characters of server text. A secret that
        # straddles the cut must not leak even partly.
        secret = "sk-live-0123456789abcdefghijklmnopqrstuv"
        path = os.path.join(self.tmp(), "r.json")
        prefix_len = len("bad request, your key ")
        for pad in (51, 70, 90 - prefix_len - len(secret) + 1, 40 - prefix_len - 5):
            stub = StubServer(self)
            stub.error_prefix = "x" * max(pad, 0)
            code, out, err = run_cli("run", "--url", stub.url, "--header-env", "X-K=V",
                                     "--error-probes", "--json", path, env={"V": secret})
            with open(path, encoding="utf-8") as fh:
                blob = fh.read()
            for leaked in (secret[:8], secret[8:16], secret[-8:]):
                self.assertNotIn(leaked, out + err + blob, f"pad={pad}")

    def test_run_redacts_echoed_secret_in_definitions(self):
        stub = StubServer(self)
        stub.echo_definitions = True
        path = os.path.join(self.tmp(), "r.json")
        code, out, err = run_cli("run", "--url", stub.url, "--header-env", "X-K=V", "--json", path,
                                 env={"V": self.SECRET})
        with open(path, encoding="utf-8") as fh:
            blob = fh.read()
        self.assertIn("lookup", out)
        self.assertNotIn(self.SECRET, out + err + blob)

    def test_lock_refuses_when_definitions_echo_secret(self):
        stub = StubServer(self)
        stub.echo_definitions = True
        lock = os.path.join(self.tmp(), "x.lock")
        code, out, err = run_cli("lock", "--url", stub.url, "--header-env", "X-K=V", "--lock", lock,
                                 env={"V": self.SECRET})
        self.assertEqual(code, 2)
        self.assertIn("nothing was written", err)
        self.assertFalse(os.path.exists(lock))
        self.assertNotIn(self.SECRET, out + err)

    def test_lock_writes_when_nothing_is_echoed(self):
        stub = StubServer(self)
        lock = os.path.join(self.tmp(), "x.lock")
        code, _, _ = run_cli("lock", "--url", stub.url, "--header-env", "X-K=V", "--lock", lock,
                             env={"V": self.SECRET})
        self.assertEqual(code, 0)
        with open(lock, encoding="utf-8") as fh:
            self.assertNotIn(self.SECRET, fh.read())

    def test_lock_allows_endpoint_and_literal_header_in_definitions(self):
        # Benign near-miss: a plain URL and a --header value aren't secret, so a tool
        # that mentions its endpoint or the client name must still lock.
        stub = StubServer(self)
        stub.description_suffix = f" Docs: {stub.url} (works with mcp-lint-client)."
        lock = os.path.join(self.tmp(), "x.lock")
        code, _, err = run_cli("lock", "--url", stub.url, "--header", "X-Client: mcp-lint-client",
                               "--header-env", "X-K=V", "--lock", lock, env={"V": self.SECRET})
        self.assertEqual(code, 0, err)
        with open(lock, encoding="utf-8") as fh:
            text = fh.read()
        self.assertIn("mcp-lint-client", text)
        self.assertNotIn(self.SECRET, text)

    def test_lock_refuses_when_url_query_token_is_echoed(self):
        stub = StubServer(self)
        stub.description_suffix = " token=QTOKEN123"
        lock = os.path.join(self.tmp(), "x.lock")
        code, out, err = run_cli("lock", "--url", stub.url + "?token=QTOKEN123", "--lock", lock)
        self.assertEqual(code, 2)
        self.assertFalse(os.path.exists(lock))
        self.assertNotIn("QTOKEN123", out + err)

    def test_init_fixtures_refuses_when_definitions_echo_secret(self):
        stub = StubServer(self)
        stub.echo_definitions = True
        out_path = os.path.join(self.tmp(), "fx.json")
        code, out, err = run_cli("init-fixtures", out_path, "--url", stub.url,
                                 "--header-env", "X-K=V", env={"V": self.SECRET})
        self.assertEqual(code, 2)
        self.assertFalse(os.path.exists(out_path))
        self.assertNotIn(self.SECRET, out + err)

    def test_lock_check_redacts_echoed_secret(self):
        stub = StubServer(self)
        d = self.tmp()
        lock, report = os.path.join(d, "x.lock"), os.path.join(d, "c.json")
        self.assertEqual(run_cli("lock", "--url", stub.url, "--header-env", "X-K=V", "--lock", lock,
                                 env={"V": self.SECRET})[0], 0)
        stub.echo_definitions = True
        code, out, err = run_cli("lock", "--check", "--url", stub.url, "--header-env", "X-K=V",
                                 "--lock", lock, "--json", report, env={"V": self.SECRET})
        with open(report, encoding="utf-8") as fh:
            blob = fh.read()
        self.assertEqual(code, 1)  # the description changed
        self.assertNotIn(self.SECRET, out + err + blob)

    def test_lock_over_existing_lock_refuses_and_keeps_it(self):
        stub = StubServer(self)
        lock = os.path.join(self.tmp(), "x.lock")
        run_cli("lock", "--url", stub.url, "--header-env", "X-K=V", "--lock", lock, env={"V": self.SECRET})
        with open(lock, encoding="utf-8") as fh:
            before = fh.read()
        stub.echo_definitions = True
        code, out, err = run_cli("lock", "--url", stub.url, "--header-env", "X-K=V", "--lock", lock,
                                 "--accept", env={"V": self.SECRET})
        self.assertEqual(code, 2)
        with open(lock, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), before)
        self.assertNotIn(self.SECRET, out + err)


class Recorder:
    """A raw TCP listener that records what it receives and then closes the connection."""

    def __init__(self, testcase):
        self.received = b""
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.port = self.sock.getsockname()[1]
        self.sock.settimeout(0.2)
        self.stop = threading.Event()
        t = threading.Thread(target=self._loop, daemon=True)
        t.start()
        testcase.addCleanup(t.join, 5)
        testcase.addCleanup(self.stop.set)

    def _loop(self):
        while not self.stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except OSError:
                continue
            with conn:
                conn.settimeout(1)
                try:
                    self.received += conn.recv(65536)
                except OSError:
                    pass
        self.sock.close()


class EnvProxyTests(unittest.TestCase):
    def test_env_proxy_never_receives_secret_over_http(self):
        proxy, target = Recorder(self), Recorder(self)
        env = {"V": "PROXYSECRET", "HTTP_PROXY": f"http://127.0.0.1:{proxy.port}",
               "http_proxy": f"http://127.0.0.1:{proxy.port}",
               "ALL_PROXY": f"http://127.0.0.1:{proxy.port}",
               "all_proxy": f"http://127.0.0.1:{proxy.port}", "NO_PROXY": "", "no_proxy": ""}
        code, out, err = run_cli("run", "--url", f"http://127.0.0.1:{target.port}/mcp",
                                 "--header-env", "X-K=V", env=env)
        time.sleep(0.5)
        self.assertEqual(code, 2)
        self.assertNotIn(b"PROXYSECRET", proxy.received)
        self.assertEqual(proxy.received, b"")

    def test_client_trust_env_only_for_https(self):
        from mcp_lint.client import build_http_client

        self.assertFalse(build_http_client(HttpTarget("http://127.0.0.1:1/mcp")).trust_env)
        self.assertFalse(build_http_client(HttpTarget("http://example.com/mcp")).trust_env)
        self.assertTrue(build_http_client(HttpTarget("https://example.com/mcp")).trust_env)

    def test_client_does_not_follow_redirects(self):
        from mcp_lint.client import build_http_client

        self.assertFalse(build_http_client(HttpTarget("https://example.com/mcp")).follow_redirects)


class HardeningTests(unittest.TestCase):
    URL = "https://h.example/mcp"

    def test_trailing_newline_in_header_name(self):
        with self.assertRaises(HttpConfigError):
            parse_headers(self.URL, ["X-A\n: v"])
        with self.assertRaises(HttpConfigError):
            parse_headers(self.URL, [], ["X-A\n=V"], {"V": "x"})

    def test_cli_trailing_newline_in_header_name(self):
        for flag, val in (("--header", "X-A\n: v"), ("--header-env", "X-A\n=V")):
            with mock.patch("mcp_lint.client.fetch_tools_http") as connect:
                code, _, _ = run_cli("run", "--url", self.URL, flag, val, env={"V": "x"})
            connect.assert_not_called()
            self.assertEqual(code, 2, flag)

    def test_control_characters_in_values(self):
        for bad in ("a\x01b", "a\x7fb", "a\tb", "a\x00b"):
            with self.assertRaises(HttpConfigError, msg=repr(bad)):
                parse_headers(self.URL, [f"X-A: {bad}"])
            with self.assertRaises(HttpConfigError, msg=repr(bad)):
                parse_headers(self.URL, [], ["X-A=V"], {"V": bad})

    def test_run_routes_oserror_through_redaction(self):
        port = free_port()
        url = f"http://127.0.0.1:{port}/mcp?token=QUERYSECRET"
        with mock.patch("mcp_lint.client.fetch_tools_http",
                        side_effect=OSError("boom QUERYSECRET HDRSECRET")):
            code, out, err = run_cli("run", "--url", url, "--header-env", "X-K=V", env={"V": "HDRSECRET"})
        self.assertEqual(code, 2)
        self.assertNotIn("QUERYSECRET", out + err)
        self.assertNotIn("HDRSECRET", out + err)
        self.assertIn("could not connect to http://127.0.0.1", err)

    def test_lookalike_hosts_are_not_loopback(self):
        for url in ("http://127.0.0.1.evil.com/", "http://localhost.evil.com/", "http://0x7f.1/",
                    "http://127.0.0.1@evil.com/", "http://localhost:@evil.com/",
                    "http://evil.com\\@127.0.0.1/", "http://127.1/", "http://localhost./"):
            with self.assertRaises(HttpConfigError, msg=url):
                parse_headers(url, [], ["X-K=V"], {"V": "x"})

    def test_value_typed_instead_of_variable_name_is_not_echoed(self):
        with self.assertRaises(HttpConfigError) as cm:
            parse_headers(self.URL, [], ["X-Key=sk-live-abc"], {})
        self.assertNotIn("sk-live-abc", str(cm.exception))
        self.assertIn("environment variable name", str(cm.exception))

    def test_punycode_and_unicode_hosts_are_accepted(self):
        from mcp_lint.client import validate_url

        validate_url("https://xn--bcher-kva.example/mcp")
        validate_url("https://bücher.example/mcp")
        validate_url("http://[::1]:8000/mcp")

    def test_plain_url_and_literal_headers_are_not_secret(self):
        from mcp_lint.client import secret_strings

        self.assertEqual(secret_strings("https://h.example/mcp"), [])
        self.assertIn("https://h.example/mcp?t=TOKENX", secret_strings("https://h.example/mcp?t=TOKENX"))
        target = HttpTarget("https://h.example/mcp", {"X-Client": "mcp-lint", "X-K": "SECRETV"},
                            secret_headers=frozenset({"x-k"}))
        self.assertEqual(target.secret_values(), {"X-K": "SECRETV"})
        # Without secret_headers every header counts (fail closed).
        self.assertEqual(HttpTarget("https://h/mcp", {"A": "VALUE"}).secret_values(), {"A": "VALUE"})

    def test_secret_set_ignores_short_values_and_covers_escapes(self):
        from mcp_lint.client import secret_strings

        target = HttpTarget("https://us3r:pw@h.example/mcp?a=abc&token=TOKENVALUE",
                            {"X-A": "ab", "X-B": 'qu"oteé'})
        secrets = secret_strings(target.url, target.headers)
        self.assertIn("TOKENVALUE", secrets)
        self.assertIn("us3r", secrets)
        self.assertNotIn("pw", secrets)
        self.assertNotIn("abc", secrets)
        self.assertNotIn("ab", secrets)
        self.assertIn('qu\\"oteé', secrets)
        self.assertIn('qu\\"ote\\u00e9', secrets)


if __name__ == "__main__":
    unittest.main()
