"""Connect to an MCP server over stdio or Streamable HTTP: list its tools and run probe calls."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import sys
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import AsyncIterator, Mapping
from urllib.parse import parse_qsl, urlsplit

import httpx2
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client
from mcp.shared._httpx_utils import MCP_DEFAULT_SSE_READ_TIMEOUT, MCP_DEFAULT_TIMEOUT
from mcp.types import PaginatedRequestParams

from mcp_lint.fixtures import Probe, error_probes
from mcp_lint.models import ToolDef
from mcp_lint.probe import ProbeResult, call_probe


@dataclass
class ServerInfo:
    name: str
    version: str
    tools: list[ToolDef]
    instructions: str = ""  # the initialize result's instructions; "" when the server sends none


def _resolve_command(command: str) -> str:
    """Find the executable, including Windows shims like ``npx.cmd``."""
    found = shutil.which(command)
    return found or command


def _plain(value):
    """A pydantic value (or list of them) as plain JSON data; None becomes empty."""
    if value is None:
        return None
    if isinstance(value, list):
        return [_plain(v) for v in value]
    dump = getattr(value, "model_dump", None)
    if dump is not None:
        return dump(by_alias=True, exclude_none=True, mode="json")
    return value


async def _list_tools(session: ClientSession) -> list[ToolDef]:
    tools: list[ToolDef] = []
    cursor: str | None = None
    while True:
        req = PaginatedRequestParams(cursor=cursor) if cursor else None
        result = await session.list_tools(params=req)
        for t in result.tools:
            annotations = t.annotations.model_dump(by_alias=True, exclude_none=True) if t.annotations else {}
            tools.append(
                ToolDef(
                    name=t.name,
                    description=t.description,
                    input_schema=dict(t.input_schema or {}),
                    annotations=annotations,
                    title=t.title,
                    output_schema=dict(t.output_schema or {}),
                    meta=dict(_plain(t.meta) or {}),
                    icons=list(_plain(t.icons) or []),
                    execution=dict(_plain(t.execution) or {}),
                )
            )
        cursor = result.next_cursor
        if not cursor:
            return tools


def server_env(pass_env: list[str] | None = None) -> dict[str, str]:
    """Extra variables to give the server, on top of the SDK's safe defaults.

    The SDK passes only a minimal set (PATH, TEMP, USERPROFILE/HOME, ...), so
    API keys and tokens in the user's environment never reach a server unless
    named here. Unset names are skipped.
    """
    return {name: os.environ[name] for name in (pass_env or []) if name in os.environ}


@asynccontextmanager
async def _open_session(read, write) -> AsyncIterator[tuple[ClientSession, ServerInfo]]:
    """Initialise a session on an open transport and list the tools (shared by stdio and HTTP)."""
    async with ClientSession(read, write) as session:
        init = await session.initialize()
        tools = await _list_tools(session)
        info = init.server_info
        yield session, ServerInfo(
            name=info.name, version=info.version, tools=tools,
            instructions=init.instructions or "")


@asynccontextmanager
async def connect(command: str, args: list[str],
                  pass_env: list[str] | None = None) -> AsyncIterator[tuple[ClientSession, ServerInfo]]:
    params = StdioServerParameters(
        command=_resolve_command(command),
        args=args,
        env=server_env(pass_env),
    )
    async with stdio_client(params, errlog=sys.stderr) as (read, write):
        async with _open_session(read, write) as result:
            yield result


# --- Streamable HTTP -------------------------------------------------------

class HttpConfigError(ValueError):
    """A bad --url or header option. The message never contains a header value."""


@dataclass
class HttpTarget:
    url: str  # may hold tokens: never print it
    headers: dict[str, str] = field(default_factory=dict, repr=False)
    # Lower-cased names of headers whose values are secret (from --header-env).
    # None means every header counts as secret (the fail-closed default).
    secret_headers: frozenset[str] | None = field(default=None, repr=False)

    def secret_values(self) -> dict[str, str]:
        """The headers whose values must never reach output, reports or the lock."""
        if self.secret_headers is None:
            return dict(self.headers)
        return {k: v for k, v in self.headers.items() if k.lower() in self.secret_headers}

    def __repr__(self) -> str:
        return f"HttpTarget(url={origin_of(self.url)!r})"


_TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")  # RFC 7230 token; used with fullmatch
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")  # C0 controls (tab included) and DEL
_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
MIN_SECRET_LEN = 4  # shorter values are not redacted: it would only mangle ordinary text


def origin_of(url: str) -> str:
    from mcp_lint.install import remote_origin

    return remote_origin(url)


def is_loopback_host(host: str | None) -> bool:
    if not host:
        return False
    host = host.strip("[]").lower()
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def validate_url(url: str) -> None:
    """Raise HttpConfigError unless url is http(s) with a host. Never echoes the url."""
    if _CONTROL.search(url) or "\\" in url or " " in url:
        raise HttpConfigError("--url contains a space, backslash or control character")
    try:
        parts = urlsplit(url)
        host = parts.hostname
        parts.port  # noqa: B018 - raises ValueError on a bad port
        other = httpx2.URL(url).raw_host.decode("ascii")  # ASCII form: punycode for IDNs
    except (ValueError, httpx2.InvalidURL):
        raise HttpConfigError("--url is not a valid URL") from None
    if parts.scheme not in ("http", "https"):
        raise HttpConfigError("--url must start with http:// or https://")
    if not host:
        raise HttpConfigError("--url has no host")
    try:
        ascii_host = host if host.isascii() else host.encode("idna").decode("ascii")
    except UnicodeError:
        raise HttpConfigError("--url host is ambiguous") from None
    if other.lower().strip("[]") != ascii_host.lower():
        raise HttpConfigError("--url host is ambiguous")  # two parsers disagree: don't guess


def parse_headers(url: str, literal: list[str] | None = None, from_env: list[str] | None = None,
                  environ: Mapping[str, str] | None = None) -> dict[str, str]:
    """Validate --url, --header and --header-env and return the headers to send.

    Raises HttpConfigError before anything touches the network. Messages name
    headers and variables but never a value.
    """
    environ = os.environ if environ is None else environ
    validate_url(url)
    headers: dict[str, str] = {}
    seen: set[str] = set()

    def add(name: str, value: str, what: str) -> None:
        if not _TOKEN.fullmatch(name):
            raise HttpConfigError("invalid header name (letters, digits and !#$%&'*+-.^_`|~ only)")
        if _CONTROL.search(value):
            raise HttpConfigError(f"header '{name}': {what} contains a control character")
        if name.lower() in seen:
            raise HttpConfigError(f"header '{name}' given more than once")
        seen.add(name.lower())
        headers[name] = value.strip(" ")

    parts = urlsplit(url)
    if from_env and parts.scheme == "http" and not is_loopback_host(parts.hostname):
        raise HttpConfigError(
            "refusing --header-env over unencrypted http:// to a non-local host: "
            "secrets are not sent over unencrypted HTTP (use https://)")
    for item in literal or []:
        name, sep, value = item.partition(":")
        if not sep:
            raise HttpConfigError("--header needs the form 'Name: value'")
        add(name, value, "value")
    for item in from_env or []:
        name, sep, var = item.partition("=")
        if not sep or not _ENV_NAME.fullmatch(var):
            raise HttpConfigError(
                "--header-env needs Name=VAR where VAR is an environment variable name")
        if var not in environ:
            raise HttpConfigError(
                f"environment variable {var} (for header '{name}') is not set")
        add(name, environ[var], f"the value of {var}")
    return headers


def _forms(value: str) -> list[str]:
    """A string as it appears raw and inside JSON text (ASCII-escaped or not)."""
    return [value, json.dumps(value)[1:-1], json.dumps(value, ensure_ascii=False)[1:-1]]


def secret_strings(url: str, headers: Mapping[str, str] | None = None) -> list[str]:
    """Every string that must never reach output, longest first.

    The URL's userinfo, query and query values, the given header values, and the
    full URL when it carries userinfo or a query; parts shorter than MIN_SECRET_LEN
    are skipped. A plain URL isn't secret: a server may mention its own endpoint.
    """
    parts_: set[str] = set()
    has_secret_part = True  # an unparsable URL is treated as secret
    try:
        parts = urlsplit(url)
        parts_.update([parts.query, parts.username or "", parts.password or ""])
        parts_.update(v for _, v in parse_qsl(parts.query))
        if "@" in parts.netloc:
            parts_.add(parts.netloc.rpartition("@")[0])
        has_secret_part = bool(parts.query) or "@" in parts.netloc
    except ValueError:
        pass
    parts_.update((headers or {}).values())
    found = {f for p in parts_ if len(p) >= MIN_SECRET_LEN for f in _forms(p)}
    if has_secret_part:
        found.update(_forms(url))
    return sorted((f for f in found if f), key=len, reverse=True)


def redact_secrets(text: str, secrets: list[str]) -> str:
    for secret in secrets:
        text = text.replace(secret, "[redacted]")
    return text


def contains_secret(text: str, secrets: list[str]) -> bool:
    return any(secret in text for secret in secrets)


def redact(text: str, url: str, headers: Mapping[str, str] | None = None) -> str:
    """Replace the URL, its query, userinfo and every header value in text with [redacted]."""
    return redact_secrets(text, secret_strings(url, headers))


def describe_http_error(exc: BaseException, target: HttpTarget) -> str:
    """'could not connect to <origin>: Type: message', first leaf of any ExceptionGroup, redacted."""
    while True:
        inner = getattr(exc, "exceptions", None)
        if not inner:
            break
        exc = inner[0]
    msg = redact(str(exc), target.url, target.headers)
    return f"could not connect to {origin_of(target.url)}: {type(exc).__name__}: {msg}"


def build_http_client(target: HttpTarget) -> httpx2.AsyncClient:
    """The SDK's default timeouts, no redirects, and environment proxies only for https.

    HTTP_PROXY/ALL_PROXY would carry header secrets to the proxy in cleartext when the
    target is plain http (even on loopback), so trust_env is off there. With https a
    proxy only sees a CONNECT tunnel.
    """
    return httpx2.AsyncClient(
        headers=dict(target.headers) or None,
        timeout=httpx2.Timeout(MCP_DEFAULT_TIMEOUT, read=MCP_DEFAULT_SSE_READ_TIMEOUT),
        trust_env=urlsplit(target.url).scheme == "https",
    )


@asynccontextmanager
async def connect_http(target: HttpTarget) -> AsyncIterator[tuple[ClientSession, ServerInfo]]:
    async with build_http_client(target) as http:
        async with streamable_http_client(target.url, http_client=http) as (read, write):
            async with _open_session(read, write) as result:
                yield result


async def fetch_tools_http(target: HttpTarget) -> ServerInfo:
    async with connect_http(target) as (_, info):
        return info


async def _probe_session(session: ClientSession, info: ServerInfo, probes: list[Probe],
                         timeout: float, auto_errors: bool) -> tuple[ServerInfo, list[ProbeResult]]:
    by_name = {t.name: t for t in info.tools}
    if auto_errors:
        probes = list(probes) + error_probes(info.tools)
    results = [await call_probe(session, p, by_name, timeout) for p in probes]
    return info, results


async def fetch_and_probe_http(target: HttpTarget, probes: list[Probe], timeout: float,
                               auto_errors: bool = False) -> tuple[ServerInfo, list[ProbeResult]]:
    async with connect_http(target) as (session, info):
        return await _probe_session(session, info, probes, timeout, auto_errors)


async def fetch_tools(command: str, args: list[str], pass_env: list[str] | None = None) -> ServerInfo:
    async with connect(command, args, pass_env) as (_, info):
        return info


async def fetch_and_probe(
    command: str, args: list[str], probes: list[Probe], timeout: float,
    auto_errors: bool = False, pass_env: list[str] | None = None,
) -> tuple[ServerInfo, list[ProbeResult]]:
    """List tools, then run each runnable probe in order on the same session.

    With ``auto_errors``, bad-argument probes generated from the schemas of
    read-only tools run after the fixture probes.
    """
    async with connect(command, args, pass_env) as (session, info):
        return await _probe_session(session, info, probes, timeout, auto_errors)
