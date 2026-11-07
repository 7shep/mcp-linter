"""Install lint (I1): how an MCP server is launched.

A launcher such as ``npx pkg`` or ``uvx pkg`` fetches the newest matching release
every time the server starts, so one malicious release reaches every user who
runs it unpinned. This module checks launch commands, and the servers in MCP
client config files, for unpinned packages and sources, container images
without a digest, pip installs without hashes, and known-bad releases.

Two layers decide what is refused:

* a parser that understands launchers, wrappers (shells, cmd, env) and their
  options, and reports the usual kinds, and
* a backstop that scans every argv string, split into pieces, for a known-bad
  name and version. It runs on every input whatever the program, so an option
  the parser doesn't know can't hide a known-bad release. It only ever adds
  ``known_bad`` findings.

``lint_command`` takes an argv list (not a shell string) and never raises.
Findings quote only the flagged spec or image, redacted and capped.
"""

from __future__ import annotations

import json
import re
import shlex
from dataclasses import dataclass

from mcp_lint.models import Finding, Severity

# Exact releases that must not be launched, as written. Matching normalises both
# sides (see _match_known_bad), so spellings such as "LiteLLM==1.82.8" match.
KNOWN_BAD: dict[str, dict[str, frozenset[str]]] = {
    # postmark-mcp 1.0.16 (Sept 2025): a backdoor that BCC'd every email to an attacker.
    "npm": {"postmark-mcp": frozenset({"1.0.16"})},
    # litellm 1.82.7 and 1.82.8 (Mar 2026), 1.107.0 (Oct 2026): credential stealers.
    "pypi": {"litellm": frozenset({"1.82.7", "1.82.8", "1.107.0"})},
}

_SEVERITY = {
    "unpinned": Severity.WARNING,
    "unpinned_source": Severity.WARNING,
    "no_digest": Severity.WARNING,
    "no_hashes": Severity.WARNING,
    "unreadable_entry": Severity.WARNING,
    "known_bad": Severity.ERROR,
    "unparsed": Severity.INFO,
}

_CAP = 200  # quoted specs and images are cut to this many characters
_MAX_DEPTH = 8  # shells and cmd wrappers nested this deep are reported as unparsed
_MAX_EQUALS = 64  # backstop: "=" positions tried inside one piece
_VARIANT_BUDGET = 8  # backstop: "=" suffixes tried per piece, in multiples of the piece length
_MAX_OFFSET = 32  # unknown prefix wrappers: the parser is retried from argv[1:] up to argv[32:]
_MAX_PARTS = 256  # range clauses, union members and comparators looked at per spec
_MAX_BASENAME = 1024  # artifact file names longer than this are not parsed
_MAX_DIGITS = 18  # version numbers with more digits than this are not compared

_SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "fish"})
_PWSH = frozenset({"powershell", "pwsh"})
_PREFIX_WORDS = frozenset({"exec", "nohup", "call", "then", "do", "else", "if"})
_SEP_CHARS = frozenset("();<>|&{}")
_SUBST = re.compile(r"\$\(|`|(?<![A-Za-z0-9_])(?:while|for|until|case)(?![A-Za-z0-9_])")
_PIECE_RUN = re.compile(r"[^\s\"';&|(){}\[]+")
_SEP_RUN = re.compile(r"[\s\"';&|(){}]+")
_ESCAPES = str.maketrans("", "", "\\`")
_CARET = re.compile(r"(?<![@=<>~|\s])\^")  # cmd's escape, but not the semver caret in x@^1.2
_REDIRECT = re.compile(r"[<>]")
_PS_ESCAPE = re.compile(r"`([^0abefnrtuv\s])")
_PY_CLAUSE = re.compile(r"(===|==|~=|!=|<=|>=|<|>)\s*(.*)", re.DOTALL)
_NPM_PART = r"(?:[xX*]|[0-9]{1,18})"
_NPM_PARTIAL = re.compile(
    rf"({_NPM_PART})(?:\.({_NPM_PART})(?:\.({_NPM_PART})(?:-([0-9A-Za-z.\-]+))?)?)?")
_NPM_OP = re.compile(r"<=|>=|~>|[<>=~^]")
_NPM_GLUE = re.compile(r"(<=|>=|~>|[<>=~^])\s+")
_ART_NPM = re.compile(r"(.+?)-([0-9]+\.[0-9]+\.[0-9]+.*?)\.tgz", re.IGNORECASE)
_ART_WHEEL = re.compile(r"([^-]+)-([^-]+)-.+\.whl", re.IGNORECASE)
_ART_SDIST = re.compile(r"(.+?)-([0-9][^-]*?)\.(?:tar\.gz|zip)", re.IGNORECASE)
_SEMVER = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?")
_SHA40 = re.compile(r"[0-9a-fA-F]{40}")
_ENV_ASSIGN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")
_URL = re.compile(r"https?://", re.IGNORECASE)
_URL_START = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]{0,31}://")
_URL_END = re.compile(r"[\s'\"<>]")
_DIGEST = re.compile(r"@sha256:[0-9a-fA-F]{64}(?![0-9A-Za-z])")
_IMAGE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@+-]*")
_PY_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
_PY_HEAD = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*(?:\[[^\]]*\])?")
_PY_VERSION = re.compile(r"v?[0-9][0-9A-Za-z.+!_-]*")
_RELEASE = re.compile(r"[0-9]+(?:\.[0-9]+)*")
_PY_NAME_RE = re.compile(r"python(?:[0-9]+(?:\.[0-9]+)?)?|py")
_PIP_NAME_RE = re.compile(r"pip(?:[0-9]+(?:\.[0-9]+)?)?")

# Launcher options that take a value (the next token, or the --x=y / -xVALUE form).
_UV_VALUE = frozenset({
    "--with", "-w", "--with-editable", "--with-requirements", "--env-file", "--directory",
    "--project", "--cache-dir", "-c", "--constraints", "-b", "--build-constraints", "--overrides",
    "-f", "--find-links", "-i", "--index-url", "-P", "--upgrade-package", "-C", "--config-setting",
    "--refresh-package", "--reinstall-package", "--index-strategy", "--keyring-provider",
    "--resolution", "--prerelease", "--exclude-newer", "--link-mode", "--color", "--config-file",
    "--python-platform", "--allow-insecure-host", "--from", "--python", "-p", "--index",
    "--extra-index-url", "--default-index", "--spec",
})
_WITH_FLAGS = frozenset({"--with", "-w", "--with-editable"})
_NPM_VALUE = frozenset({
    "--cache", "--registry", "--prefix", "--userconfig", "-w", "--workspace", "-c", "--call",
    "--node-options", "-p", "--package",
})
_PIP_VALUE = frozenset({
    "--log", "--proxy", "--retries", "--timeout", "--exists-action", "--trusted-host", "--cert",
    "--client-cert", "--cache-dir", "--src", "--index-url", "-i", "--extra-index-url",
})
_DOCKER_VALUE = frozenset("""
    -e --env --env-file -v --volume --mount --name -p --publish --network --net -w --workdir
    -u --user --entrypoint --platform -l --label --add-host --cpus -m --memory --pull --runtime
    --cap-add --cap-drop --device --security-opt --tmpfs --ulimit -h --hostname --log-driver
    --log-opt --restart --gpus -a --attach --dns --dns-option --dns-search --ip --ip6 --link
    --expose --shm-size --pid --ipc --uts --group-add --sysctl --health-cmd --health-interval
    --health-retries --health-timeout --health-start-period --stop-signal --stop-timeout
    --cidfile --annotation --cpuset-cpus --cpuset-mems --memory-swap --memory-reservation
    --blkio-weight --isolation --cgroupns --userns --mac-address --cpu-shares -c
""".split())


@dataclass(frozen=True)
class ConfigServer:
    """One server from a client config. ``argv`` is set for local servers, ``url`` for remote
    ones. ``reason`` is set (and argv and url are None) when the entry can't be read."""

    name: str
    argv: list[str] | None
    url: str | None
    reason: str | None = None


@dataclass(frozen=True)
class _Hit:
    """A finding plus the package it is about, so other kinds for that package can be dropped."""

    finding: Finding
    pkg: tuple[str, str] | None = None  # (ecosystem, normalised name)
    version: str | None = None  # normalised version, for known_bad dedupe


# --- normalisation ---------------------------------------------------------

def _norm_pypi_name(name: str) -> str:
    # Stricter than PEP 503 on purpose: separators are dropped, so "Lite.LLM" matches litellm.
    # This only widens what is refused.
    return re.sub(r"[-_.]", "", name).lower()


def _ints(parts: list[str]) -> tuple[int, ...] | None:
    """Parts as ints (so 016 is 16), or None if one has too many digits to compare."""
    out: list[int] = []
    for part in parts:
        part = part.lstrip("0")
        if len(part) > _MAX_DIGITS:
            return None
        out.append(int(part or "0"))
    return tuple(out)


def _py_release(version: str) -> tuple[int, ...] | None:
    """Release numbers of a PEP 440 version: no leading v, epoch 0 or +local. None if the
    version has anything but release numbers or can't be compared."""
    v = version.strip()
    if v[:1] in ("v", "V"):
        v = v[1:]
    v = v.split("+", 1)[0]
    if "!" in v:
        epoch, v = v.split("!", 1)
        if not epoch or epoch.strip("0"):
            return None
    if not _RELEASE.fullmatch(v):
        return None
    return _ints(v.split("."))


def _norm_npm_name(name: str) -> str:
    return name.lower()


def _norm_npm_version(version: str) -> str:
    """Version text without leading ``v``, ``=`` and spaces, and without ``+build``."""
    return version.lstrip("=vV \t\r\n\f").split("+", 1)[0].strip()


def _cmp(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    """Compare release tuples, padding the shorter with zeros."""
    n = max(len(a), len(b))
    a, b = a + (0,) * (n - len(a)), b + (0,) * (n - len(b))
    return (a > b) - (a < b)


def _prefix(v: tuple[int, ...], n: int) -> tuple[int, ...]:
    return (v + (0,) * n)[:n]


def _successors(v: tuple[int, ...]) -> list[tuple[int, ...]]:
    """The plausible next releases after v: next patch, next minor, next major (and the next
    release of the last part when v has more than three parts)."""
    a, b, c = (v + (0, 0, 0))[:3]
    out = [(a, b, c + 1), (a, b + 1, 0), (a + 1, 0, 0)]
    if len(v) > 3:
        out.append(v[:-1] + (v[-1] + 1,))
    return out


def _build_bad() -> dict[str, dict[str, list[tuple[int, ...]]]]:
    out: dict[str, dict[str, list[tuple[int, ...]]]] = {"npm": {}, "pypi": {}}
    for eco, table in KNOWN_BAD.items():
        for name, versions in table.items():
            norm_name = _norm_pypi_name(name) if eco == "pypi" else _norm_npm_name(name)
            for v in sorted(versions):
                rel = _ints(v.split("."))
                if rel is not None:
                    out[eco].setdefault(norm_name, []).append(rel)
    return out


_BAD = _build_bad()


def _py_clause(op: str, rel: tuple[int, ...], star: bool):
    """A predicate over release tuples for one PEP 440 clause, or None if it is not valid."""
    n = len(rel)
    if op in ("==", "==="):
        if star:
            return lambda v: _prefix(v, n) == rel
        return lambda v: _cmp(v, rel) == 0
    if op == "!=":
        if star:
            return lambda v: _prefix(v, n) != rel
        return lambda v: _cmp(v, rel) != 0
    if op == "~=":
        if n < 2:
            return None
        return lambda v: _cmp(v, rel) >= 0 and _prefix(v, n - 1) == rel[:n - 1]
    if op == "<":
        return lambda v: _cmp(v, rel) < 0
    if op == "<=":
        return lambda v: _cmp(v, rel) <= 0
    if op == ">":
        return lambda v: _cmp(v, rel) > 0
    return lambda v: _cmp(v, rel) >= 0


def _py_admitters(constraint: str) -> list:
    """One predicate for a PEP 440 specifier set (``>=1,<2``, ``==1.2.*``, ``~=1.2``...) over
    release tuples. An empty list if any clause can't be understood."""
    text = constraint.strip()
    if text.startswith("(") and text.endswith(")"):
        text = text[1:-1]
    parts = list(dict.fromkeys(p.strip() for p in text.split(",") if p.strip()))
    if not parts or len(parts) > _MAX_PARTS:
        return []
    preds = []
    for part in parts:
        m = _PY_CLAUSE.fullmatch(part)
        if m is None:
            return []
        op, ver = m.group(1), m.group(2).strip()
        star = ver.endswith(".*")
        if star:
            if op not in ("==", "!="):
                return []
            ver = ver[:-2]
        rel = _py_release(ver)
        pred = None if rel is None else _py_clause(op, rel, star)
        if pred is None:
            return []
        preds.append(pred)
    return [lambda v: all(p(v) for p in preds)]


def _npm_partial(text: str):
    """(major, minor, patch, is_prerelease) of a possibly partial version; a missing or
    wildcard part is None. None if the text is not a version."""
    body = _norm_npm_version(text)
    m = _NPM_PARTIAL.fullmatch(body)
    if m is None:
        return None
    nums: list[int | None] = [None if g is None or g in ("x", "X", "*") else int(g)
                              for g in m.groups()[:3]]
    for i in (1, 2):
        if nums[i - 1] is None:
            nums[i] = None
    return nums[0], nums[1], nums[2], m.group(4) is not None


def _npm_comparator(tok: str):
    """A predicate over (major, minor, patch) for one comparator, or None if it can't be read."""
    m = _NPM_OP.match(tok)
    op = m.group(0) if m else "="
    part = _npm_partial(tok[m.end():] if m else tok)
    if part is None:
        return None
    major, minor, patch, pre = part
    never = lambda v: False  # noqa: E731
    always = lambda v: True  # noqa: E731
    if major is None:
        return never if op in (">", "<") else always
    low = (major, minor or 0, patch or 0)
    next_part = (major + 1, 0, 0) if minor is None else (major, minor + 1, 0)
    if op in ("~", "~>"):
        return lambda v: low <= v < next_part
    if op == "^":
        if major > 0:
            hi = (major + 1, 0, 0)
        elif minor is None:
            hi = (1, 0, 0)
        elif minor > 0 or patch is None:
            hi = (0, minor + 1, 0)
        else:
            hi = (0, 0, patch + 1)
        return lambda v: low <= v < hi
    if op == "=":
        if patch is None:
            return lambda v: low <= v < next_part
        return never if pre else (lambda v: v == low)
    if op == ">=":
        return lambda v: v >= low
    if op == ">":
        if patch is None:
            return lambda v: v >= next_part
        return (lambda v: v >= low) if pre else (lambda v: v > low)
    if op == "<":
        return lambda v: v < low
    # "<="
    if patch is None:
        return lambda v: v < next_part
    return (lambda v: v < low) if pre else (lambda v: v <= low)


def _npm_member(text: str):
    """A predicate for one ``||`` member (comparators separated by spaces), or None."""
    toks = list(dict.fromkeys(_NPM_GLUE.sub(r"\1", text).split()))[:_MAX_PARTS]
    preds = []
    i = 0
    while i < len(toks):
        if i + 2 < len(toks) and toks[i + 1] == "-":
            pair = (">=" + toks[i], "<=" + toks[i + 2])
            i += 3
        else:
            pair = (toks[i],)
            i += 1
        for tok in pair:
            pred = _npm_comparator(tok)
            if pred is None:
                return None
            preds.append(pred)
    return lambda v: all(p(v) for p in preds)


def _npm_admitters(constraint: str) -> list:
    """One predicate per ``||`` member of an npm range. A member that can't be read is left out."""
    out = []
    for member in constraint.split("||")[:_MAX_PARTS]:
        pred = _npm_member(member)
        if pred is not None:
            out.append(pred)
    return out


def _match_known_bad(eco: str, name: str, constraint: str) -> tuple[str, str] | None:
    """(normalised name, bad version) if the version constraint admits a known-bad release and
    none of its plausible successors, so a resolver picking the highest match gets the bad one.
    An exact pin is the simplest case. Never raises on odd input."""
    nname = _norm_pypi_name(name) if eco == "pypi" else _norm_npm_name(name)
    bads = _BAD[eco].get(nname)
    if not bads:
        return None
    admitters = _py_admitters(constraint) if eco == "pypi" else _npm_admitters(constraint)
    for admits in admitters:
        for bad in bads:
            if admits(bad) and not any(admits(s) for s in _successors(bad)):
                return nname, ".".join(str(n) for n in bad)
    return None


# --- findings --------------------------------------------------------------

def _q(text: str) -> str:
    """Text safe to quote in a message: URL userinfo, query and fragment removed, capped."""
    text = _redact(text)
    return text if len(text) <= _CAP else text[:_CAP] + "…"


def _clean_url(url: str) -> str:
    scheme, _, rest = url.partition("://")
    slash = rest.find("/")
    auth, path = (rest, "") if slash < 0 else (rest[:slash], rest[slash:])
    # The authority is everything up to the first "/", so a "#" or "?" inside a password stays
    # in it and goes with the userinfo. Only then are the query and fragment dropped.
    if "@" in auth:
        auth = "***@" + auth.rsplit("@", 1)[1]
    auth = auth.split("?", 1)[0].split("#", 1)[0]
    path = path.split("?", 1)[0].split("#", 1)[0]
    return f"{scheme}://{auth}{path}"


def _redact(text: str) -> str:
    """Drop URL userinfo, query and fragment: ``https://user:pass@host/x?k=v#f`` becomes
    ``https://***@host/x``. Linear in the input length."""
    out: list[str] = []
    pos = 0
    for m in _URL_START.finditer(text):
        if m.start() < pos:
            continue
        end_m = _URL_END.search(text, m.end())
        end = end_m.start() if end_m else len(text)
        out.append(text[pos:m.start()])
        out.append(_clean_url(text[m.start():end]))
        pos = end
    out.append(text[pos:])
    return "".join(out)


def _hit(kind: str, message: str, hint: str | None, pkg: tuple[str, str] | None = None,
         version: str | None = None) -> _Hit:
    return _Hit(Finding(rule="I1", severity=_SEVERITY[kind], tool=None, message=message,
                        hint=hint, kind=kind), pkg, version)


def _unparsed(why: str) -> _Hit:
    return _hit("unparsed", f"{why}; mcp-lint did not check that part of the command",
                "write the launch command as separate arguments so it can be checked")


def _unpinned(eco: str, spec: str, name: str, example: str) -> _Hit:
    norm = _norm_pypi_name(name) if eco == "pypi" else _norm_npm_name(name)
    return _hit(
        "unpinned",
        f'"{_q(spec)}" has no exact version pin, so each start may run a different release',
        f'pin an exact version, e.g. "{_q(example)}"',
        pkg=(eco, norm),
    )


def _unpinned_source(spec: str) -> _Hit:
    return _hit(
        "unpinned_source",
        f'"{_q(spec)}" is a source not pinned to a full commit SHA',
        "pin the source to a full 40-character commit SHA",
    )


def _known_hit(eco: str, name: str, constraint: str, display: str) -> _Hit | None:
    match = _match_known_bad(eco, name, constraint)
    if match is None:
        return None
    return _hit(
        "known_bad",
        f'"{_q(display)}" is a known-malicious release',
        "use a release you have reviewed instead; this version is on mcp-lint's known-bad list",
        pkg=(eco, match[0]),
        version=match[1],
    )


def unreadable_finding(name: str, reason: str) -> Finding:
    """The warning for a client config entry that mcp-lint can't read."""
    return _hit(
        "unreadable_entry",
        f'server "{_q(name)}": {reason}; it was not checked',
        "make command a string and args a list of strings, or give the server a url",
    ).finding


# --- small helpers ---------------------------------------------------------

def _is_local(spec: str) -> bool:
    return (spec.startswith((".", "/", "\\", "~")) or re.match(r"[A-Za-z]:", spec) is not None
            or spec.lower().startswith("file:"))


def _program(arg0: str) -> str:
    """Basename of argv[0], lowercased, without a Windows executable suffix."""
    base = re.split(r"[\\/]", arg0)[-1].lower()
    for suffix in (".cmd", ".exe", ".bat", ".ps1"):
        if base.endswith(suffix):
            return base[: -len(suffix)]
    return base


def _pinned_source(spec: str) -> bool:
    """A git or URL source pinned to a full commit SHA. ``#...`` fragments are ignored
    (except ``#<sha>`` for npm shorthand), so ``@<sha>#subdirectory=x`` is pinned."""
    base, _, frag = spec.partition("#")
    if "@" in base:
        ref = base.rsplit("@", 1)[1]
    else:
        ref = frag.split("#", 1)[0]
    return _SHA40.fullmatch(ref) is not None


def _is_npm_source(spec: str) -> bool:
    low = spec.lower()
    if low.startswith(("github:", "gitlab:", "bitbucket:", "gist:", "git+", "git:", "http://", "https://")):
        return True
    return "/" in spec and not spec.startswith("@")  # bare user/repo


def _split_commas(value: str) -> list[str]:
    """Split on commas that are not inside [extras]. A piece that starts with a comparison
    operator belongs to the requirement before it (``a>=1,<2`` is one requirement)."""
    raw: list[str] = []
    depth = 0
    cur: list[str] = []
    for ch in value:
        if ch == "[":
            depth += 1
        elif ch == "]" and depth:
            depth -= 1
        if ch == "," and depth == 0:
            raw.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    raw.append("".join(cur))
    out: list[str] = []
    for piece in raw:
        piece = piece.strip()
        if not piece:
            continue
        if out and piece[0] in "<>=!~":
            out[-1] += "," + piece
        else:
            out.append(piece)
    return out


def _short(tok: str, flags: frozenset[str]) -> tuple[str, str | None] | None:
    """For a single-dash token like -w, -wVALUE, -qw or -ie: the value flag in it, and the value
    attached to it (None means the value is the next token). None if no letter takes a value."""
    for j in range(1, len(tok)):
        flag = "-" + tok[j]
        if flag in flags:
            return flag, (tok[j + 1:] or None)
    return None


def _scan(args: list[str], flags: frozenset[str]) -> tuple[list[tuple[str, str]], int | None]:
    """Walk launcher options up to the first positional.

    Returns the (flag, value) pairs for value-taking flags and the index of the first
    positional (None if there is none).
    """
    opts: list[tuple[str, str]] = []
    i, n = 0, len(args)
    while i < n:
        tok = args[i]
        if tok == "--":
            i += 1
            break
        if not tok.startswith("-") or tok == "-":
            break
        if tok.startswith("--"):
            if "=" in tok:
                flag, value = tok.split("=", 1)
                if flag in flags:
                    opts.append((flag, value))
                i += 1
            elif tok in flags:
                if i + 1 < n:
                    opts.append((tok, args[i + 1]))
                i += 2
            else:
                i += 1
            continue
        hit = _short(tok, flags)
        if hit is None:
            i += 1
        else:
            flag, attached = hit
            if attached is not None:
                opts.append((flag, attached))
                i += 1
            else:
                if i + 1 < n:
                    opts.append((flag, args[i + 1]))
                i += 2
    return opts, (i if i < n else None)


def _after_globals(args: list[str], value_flags: frozenset[str]) -> list[str]:
    """Skip a launcher's global options, which come before its subcommand."""
    i = 0
    while i < len(args) and args[i].startswith("-") and args[i] != "-":
        i += 2 if args[i] in value_flags else 1
    return args[i:]


# --- specs -----------------------------------------------------------------

def _npm_spec(spec: str) -> list[_Hit]:
    spec = spec.strip()
    if "npm:" in spec:  # alias: x@npm:real@1.2.3 and npm:real@1.2.3 both check real@1.2.3
        spec = spec[spec.rfind("npm:") + 4:].strip()
    if not spec or _is_local(spec):
        return []
    if _is_npm_source(spec):
        return [] if _pinned_source(spec) else [_unpinned_source(spec)]
    idx = spec.rfind("@")
    name, version = (spec[:idx], spec[idx + 1:]) if idx > 0 else (spec, None)
    if version is not None:
        hit = _known_hit("npm", name, version, spec)  # exact versions and ranges
        if hit is not None:
            return [hit]
        if _SEMVER.fullmatch(_norm_npm_version(version)):
            return []
    return [_unpinned("npm", spec, name, f"{name}@1.2.3")]


def _py_pin(spec: str) -> tuple[str, str | None]:
    """(name without extras, exact version or None). ``==``, ``===``, ``(==V)`` and ``@V`` pin."""
    spec = spec.split(";", 1)[0].strip()  # environment markers
    m = _PY_NAME.match(spec)
    if m is None:
        return spec, None
    name = m.group(0)
    rest = spec[m.end():].strip()
    if rest.startswith("["):
        close = rest.find("]")
        if close < 0:
            return name, None
        rest = rest[close + 1:].strip()
    if rest.startswith("(") and rest.endswith(")"):
        rest = rest[1:-1].strip()
    if rest.startswith("==="):
        version = rest[3:]
    elif rest.startswith("=="):
        version = rest[2:]
    elif rest.startswith("@"):
        version = rest[1:]
    else:
        return name, None  # bare name, or a range such as >=, ~=, <, !=
    version = version.strip()
    return name, (version if _PY_VERSION.fullmatch(version) else None)


def _py_known(spec: str) -> _Hit | None:
    """A known_bad hit if this PEP 508 requirement's version constraint can only resolve to a
    known-bad release (an exact pin, ``@V``, ``(==V)`` or a range that admits no newer one)."""
    spec = spec.split(";", 1)[0].strip()  # environment markers
    m = _PY_NAME.match(spec)
    if m is None:
        return None
    rest = spec[m.end():].strip()
    if rest.startswith("["):
        close = rest.find("]")
        if close < 0:
            return None
        rest = rest[close + 1:].strip()
    if rest.startswith("(") and rest.endswith(")"):
        rest = rest[1:-1].strip()
    if rest.startswith("@"):
        rest = "==" + rest[1:].strip()
    return _known_hit("pypi", m.group(0), rest, spec) if rest else None


def _direct_ref(spec: str) -> str | None:
    """The URL of a PEP 508 direct reference (``name @ git+https://...``), else None."""
    at = spec.find("@")
    if at <= 0 or _PY_HEAD.fullmatch(spec[:at].strip()) is None:
        return None
    tail = spec[at + 1:].split(";", 1)[0].strip()
    if tail.startswith("git+") or _URL.match(tail):
        return tail
    return None


def _url_source(url: str) -> list[_Hit]:
    if url.startswith("git+") and _pinned_source(url):
        return []
    return [_unpinned_source(url)]


def _py_spec(spec: str) -> list[_Hit]:
    spec = spec.strip()
    if not spec or _is_local(spec):
        return []
    if spec.startswith("git+") or _URL.match(spec):
        return _url_source(spec)
    url = _direct_ref(spec)
    if url is not None:
        return _url_source(url)  # the URL half is a source; the name carries no version pin
    hit = _py_known(spec)
    if hit is not None:
        return [hit]
    name, version = _py_pin(spec)
    if version is None:
        return [_unpinned("pypi", spec, name, f"{name}==1.2.3")]
    return []


def _uv_tool_run(args: list[str]) -> list[_Hit]:
    """uvx, uv tool run, pipx run: the package is --from/--spec, else the first positional.
    Every --with (comma list) is also a spec."""
    opts, pos = _scan(args, _UV_VALUE)
    sources = [value for flag, value in opts if flag in ("--from", "--spec")]
    specs = list(sources)
    if not sources and pos is not None:
        specs.append(args[pos])
    specs += [s for flag, value in opts if flag in _WITH_FLAGS for s in _split_commas(value)]
    return [h for spec in specs for h in _py_spec(spec)]


def _uv_run(args: list[str]) -> list[_Hit]:
    """uv run: only the --with requirements are packages. The script is never checked."""
    opts, _ = _scan(args, _UV_VALUE)
    return [h for flag, value in opts if flag in _WITH_FLAGS
            for spec in _split_commas(value) for h in _py_spec(spec)]


def _uv(args: list[str]) -> list[_Hit]:
    tail = _after_globals(args, _UV_VALUE)
    if tail[:1] == ["run"]:
        return _uv_run(tail[1:])
    if tail[:2] == ["tool", "run"]:
        return _uv_tool_run(tail[2:])
    if tail[:2] == ["pip", "install"]:
        return _pip(tail[2:])
    return []


def _npm(args: list[str]) -> list[_Hit]:
    """npx, pnpx, bunx and their subcommands. -p/--package names the packages; then the first
    positional is the bin and isn't checked. Otherwise the first positional is the spec."""
    packages: list[str] = []
    i, n = 0, len(args)
    while i < n:
        tok = args[i]
        if tok in ("-p", "--package"):
            if i + 1 < n:
                packages.append(args[i + 1])
            i += 2
        elif tok.startswith("--package="):
            packages.append(tok.split("=", 1)[1])
            i += 1
        elif tok in _NPM_VALUE:
            i += 2
        elif tok.startswith("-"):
            i += 1
        else:
            break
    if packages:
        specs = packages
    elif i < n:
        specs = [args[i]]
    else:
        specs = []
    return [h for spec in specs for h in _npm_spec(spec)]


def _npm_family(prog: str, args: list[str]) -> list[_Hit]:
    if prog in ("npx", "pnpx", "bunx"):
        return _npm(args)
    tail = _after_globals(args, _NPM_VALUE)
    if prog == "bun" and tail[:1] == ["x"]:
        return _npm(tail[1:])
    if prog in ("pnpm", "yarn") and tail[:1] == ["dlx"]:
        return _npm(tail[1:])
    if prog == "npm" and tail[:1] in (["exec"], ["x"]):
        return _npm(tail[1:])
    return []


def _pip(args: list[str]) -> list[_Hit]:
    known: list[_Hit] = []
    for tok in args:
        if tok.startswith("-"):
            continue
        hit = _py_known(tok)
        if hit is not None:
            known.append(hit)
    if known:
        return known  # a known-bad pin is reported alone, not with no_hashes
    if "--require-hashes" in args:
        return []
    return [_hit(
        "no_hashes",
        "pip install without --require-hashes: the packages can change between installs",
        "pin each requirement with a hash (pip-compile --generate-hashes) and install with --require-hashes",
    )]


def _pip_cmd(args: list[str]) -> list[_Hit]:
    """Arguments after pip, pipN or python -m pip: skip global options, then install."""
    tail = _after_globals(args, _PIP_VALUE)
    if tail[:1] == ["install"]:
        return _pip(tail[1:])
    return []


def _interp_pip(args: list[str]) -> list[_Hit]:
    """python / pythonN.M / py: skip interpreter options, then -m pip (also -mpip)."""
    i, n = 0, len(args)
    while i < n:
        tok = args[i]
        if tok == "-m":
            return _pip_cmd(args[i + 2:]) if args[i + 1:i + 2] == ["pip"] else []
        if tok == "-mpip":
            return _pip_cmd(args[i + 1:])
        if not tok.startswith("-") or tok == "-":
            return []
        i += 1
    return []


def _container(args: list[str]) -> list[_Hit]:
    _, pos = _scan(args, _DOCKER_VALUE)
    if pos is None:
        return []
    image = args[pos]
    if not _IMAGE.fullmatch(image):
        return [_hit(
            "no_digest",
            "the container image could not be identified, so its digest was not checked",
            "pass the image as a plain reference, e.g. name@sha256:<64 hex digits>",
        )]
    if _DIGEST.search(image):
        return []
    return [_hit(
        "no_digest",
        f'image "{_q(image)}" is not pinned to a digest, so its tag can point at different content later',
        f'pin it by digest, e.g. "{_q(image)}@sha256:<64 hex digits>"',
    )]


def _launcher(prog: str, args: list[str]) -> list[_Hit]:
    if prog in ("npx", "pnpx", "bunx", "bun", "pnpm", "yarn", "npm"):
        return _npm_family(prog, args)
    if prog == "uvx":
        return _uv_tool_run(args)
    if prog == "uv":
        return _uv(args)
    if prog == "pipx":
        tail = _after_globals(args, _UV_VALUE)
        return _uv_tool_run(tail[1:]) if tail[:1] == ["run"] else []
    if _PIP_NAME_RE.fullmatch(prog):
        return _pip_cmd(args)
    if _PY_NAME_RE.fullmatch(prog):
        return _interp_pip(args)
    if prog in ("docker", "podman"):
        if args[:1] == ["run"]:
            return _container(args[1:])
        if prog == "docker" and args[:2] == ["container", "run"]:
            return _container(args[2:])
    return []


# --- wrappers: env, cmd, shells, powershell --------------------------------

def _split_env_string(text: str) -> tuple[list[str], list[_Hit]]:
    try:
        return shlex.split(text), []
    except ValueError:
        return [], [_unparsed("the env -S string does not parse")]


def _unwrap_env(args: list[str]) -> tuple[list[str], list[_Hit]]:
    """Drop env's NAME=value and option tokens. -S STR is split into arguments."""
    i, n = 0, len(args)
    while i < n:
        tok = args[i]
        if _ENV_ASSIGN.match(tok):
            i += 1
        elif tok in ("-u", "--unset", "-C", "--chdir"):
            i += 2
        elif tok.startswith(("--unset=", "--chdir=")):
            i += 1
        elif tok in ("-S", "--split-string"):
            if i + 1 >= n:
                return [], []
            tokens, hits = _split_env_string(args[i + 1])
            return tokens + args[i + 2:], hits
        elif tok.startswith("--split-string="):
            tokens, hits = _split_env_string(tok.split("=", 1)[1])
            return tokens + args[i + 1:], hits
        elif tok.startswith("-S") and not tok.startswith("--"):
            tokens, hits = _split_env_string(tok[2:])
            return tokens + args[i + 1:], hits
        elif tok.startswith("-"):
            i += 1
        else:
            break
    return args[i:], []


def _shell_tokens(text: str) -> list[str]:
    """Shell words, with ;  &&  ||  |  (  )  {  }  as tokens of their own.
    Newlines count as ``;``. Raises ValueError on unbalanced quotes."""
    lex = shlex.shlex(text.replace("\n", " ; "), posix=True, punctuation_chars="();<>|&{}")
    lex.whitespace_split = True
    lex.commenters = ""
    return list(lex)


def _segments(tokens: list[str]) -> list[list[str]]:
    segs: list[list[str]] = []
    cur: list[str] = []
    for tok in tokens:
        if tok and all(c in _SEP_CHARS for c in tok):
            segs.append(cur)
            cur = []
        else:
            cur.append(tok)
    segs.append(cur)
    return [s for s in segs if s]


def _lint_tokens(tokens: list[str], depth: int) -> list[_Hit]:
    out: list[_Hit] = []
    for seg in _segments(tokens):
        out += _lint(seg, depth + 1)
    return out


def _shell_string(text: str, depth: int) -> list[_Hit]:
    hits: list[_Hit] = []
    if _SUBST.search(text):
        hits.append(_unparsed("the shell string uses command substitution or a loop"))
    try:
        tokens = _shell_tokens(text)
    except ValueError:
        return hits + [_unparsed("the shell string does not parse")]
    return hits + _lint_tokens(tokens, depth)


def _is_option(tok: str) -> bool:
    return len(tok) > 1 and tok[0] in "-+"


def _c_string(args: list[str]) -> tuple[bool, str | None]:
    """(whether -c was given, the command string). Options before -c (-l, -e, --login,
    -o VAL, -lc...) and after it (-x, -o VAL, --) are skipped; the string is the first operand."""
    i, n = 0, len(args)
    while i < n:
        tok = args[i]
        if tok in ("-", "--") or not tok.startswith(("-", "+")):
            return False, None
        if tok.startswith("--"):
            i += 2 if tok in ("--rcfile", "--init-file") else 1
            continue
        if tok in ("-o", "+o", "-O", "+O"):
            i += 2
            continue
        if tok.startswith("-") and "c" in tok[1:]:
            i += 1
            while i < n:
                tok = args[i]
                if tok == "--":
                    i += 1
                    break
                if not _is_option(tok):
                    break
                i += 2 if tok in ("-o", "+o", "-O", "+O", "--rcfile", "--init-file") else 1
            return True, (args[i] if i < n else None)
        i += 1
    return False, None


def _shell(args: list[str], depth: int) -> list[_Hit]:
    found, text = _c_string(args)
    if not found:
        return []
    if text is None:
        return [_unparsed("the shell -c option has no command string")]
    return _shell_string(text, depth)


def _powershell(args: list[str], depth: int) -> list[_Hit]:
    i, n = 0, len(args)
    while i < n:
        tok = args[i]
        low = tok.lower()
        if len(low) >= 2 and "-command".startswith(low):
            body = args[i + 1:]
            if not body:
                return []
            return _shell_string(_PS_ESCAPE.sub(r"\1", " ".join(body)), depth)  # `x is x
        if len(low) >= 2 and "-encodedcommand".startswith(low):
            return [_unparsed("an encoded PowerShell command is not decoded")]
        if low in ("-executionpolicy", "-ep", "-workingdirectory", "-wd", "-inputformat",
                   "-outputformat", "-version", "-psconsolefile", "-configurationname"):
            i += 2
            continue
        if not tok.startswith("-"):
            return []  # a script file
        i += 1
    return []


def _cmd(args: list[str], depth: int) -> list[_Hit]:
    """cmd /c or /k after any switches (/d /s /q /v:on ...), also attached as /cnpx."""
    i, n = 0, len(args)
    while i < n and args[i].startswith("/") and args[i][:2].lower() not in ("/c", "/k"):
        i += 1
    if i >= n or args[i][:2].lower() not in ("/c", "/k"):
        return []
    tok = args[i]
    body = ([tok[2:]] if len(tok) > 2 else []) + args[i + 1:]
    if not body:
        return []
    body = [b.replace("^", "") for b in body]  # ^ is cmd's escape character
    if len(body) == 1:
        text = body[0]
        if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
            text = text[1:-1]  # /s with an outer pair of quotes
        return _shell_string(text, depth)
    return _lint_tokens(body, depth)


# --- the parser -------------------------------------------------------------

def _lint(argv: list[str], depth: int) -> list[_Hit]:
    if depth > _MAX_DEPTH:
        return [_unparsed("the command nests wrappers too deeply")]
    hits: list[_Hit] = []
    rest = list(argv)
    while rest:
        tok = rest[0]
        if _program(tok) == "env":
            rest, extra = _unwrap_env(rest[1:])
            hits += extra
            continue
        if _ENV_ASSIGN.match(tok) or tok in _PREFIX_WORDS or tok in ("{", "}", "(", ")"):
            rest = rest[1:]
            continue
        if tok.lower() == "start" and rest[1:2] == ["/b"]:
            rest = rest[2:]
            continue
        if tok == "command":
            rest = rest[1:]
            while rest and rest[0].startswith("-"):
                rest = rest[1:]
            continue
        break
    if not rest:
        return hits
    prog, args = _program(rest[0]), rest[1:]
    if prog == "cmd":
        return hits + _cmd(args, depth)
    if prog in _SHELLS:
        return hits + _shell(args, depth)
    if prog in _PWSH:
        return hits + _powershell(args, depth)
    return hits + _launcher(prog, args)


# --- backstop ---------------------------------------------------------------

def _pieces(text: str) -> list[str]:
    """Split on whitespace, quotes and ; & | ( ) { }. Commas stay in the piece, and so does
    anything inside [brackets] (extras), however long. Linear in the length of the text."""
    out: list[str] = []
    cur: list[str] = []
    i, n = 0, len(text)
    closes = True  # False once a "[" had no "]" after it, so later ones needn't search again
    while i < n:
        m = _PIECE_RUN.match(text, i)
        if m is not None:
            cur.append(m.group())
            i = m.end()
        elif text[i] == "[":
            close = text.find("]", i + 1) if closes else -1
            if close < 0:
                closes = False
                cur.append("[")
                i += 1
            else:
                cur.append(text[i:close + 1])
                i = close + 1
        else:
            if cur:
                out.append("".join(cur))
                cur = []
            i = _SEP_RUN.match(text, i).end()
    if cur:
        out.append("".join(cur))
    return out


def _unescaped(piece: str) -> str:
    """The piece as a shell, cmd or PowerShell would read it with escapes removed (\\ ^ `), cut
    at the first redirect (``litellm==1.82.8>/dev/null``). Used for known-bad matching only."""
    text = _CARET.sub("", piece.translate(_ESCAPES))
    m = _REDIRECT.search(text)
    return text[:m.start()] if m else text


def _variants(piece: str) -> list[str]:
    """A piece as itself, without leading dashes, and after each single "=" (--from=X, TOKEN=X).
    The "=" suffixes are bounded by a budget proportional to the piece, so a crafted piece
    can't cost quadratic time."""
    out = [piece]
    stripped = piece.lstrip("-")
    if stripped != piece:
        out.append(stripped)
    seen = 0
    budget = _VARIANT_BUDGET * len(piece) + 4096
    for k, ch in enumerate(piece):
        if ch != "=" or (k > 0 and piece[k - 1] == "=") or (k + 1 < len(piece) and piece[k + 1] == "="):
            continue
        seen += 1
        budget -= len(piece) - k - 1
        if seen > _MAX_EQUALS or budget < 0:
            break
        out.append(piece[k + 1:])
    return out


def _artifact(cand: str) -> list[_Hit]:
    """A package file name or URL: npm ``name-1.2.3.tgz``, a wheel ``name-1.2.3-py3-none-any.whl``
    or an sdist ``name-1.2.3.tar.gz`` / ``.zip``. Looks only at the file name."""
    base = re.split(r"[\\/]", cand.split("?", 1)[0].split("#", 1)[0])[-1]
    if len(base) > _MAX_BASENAME:
        return []
    low = base.lower()
    if low.endswith(".tgz"):
        m = _ART_NPM.fullmatch(base)
        eco, prefix = "npm", ""
    elif low.endswith(".whl"):
        m = _ART_WHEEL.fullmatch(base)
        eco, prefix = "pypi", "=="
    elif low.endswith((".tar.gz", ".zip")):
        m = _ART_SDIST.fullmatch(base)
        eco, prefix = "pypi", "=="
    else:
        return []
    if m is None:
        return []
    hit = _known_hit(eco, m.group(1), prefix + m.group(2), base)
    return [hit] if hit is not None else []


def _scan_candidate(cand: str) -> list[_Hit]:
    hits: list[_Hit] = []
    s = cand[cand.rfind("npm:") + 4:] if "npm:" in cand else cand
    idx = s.rfind("@")
    if idx > 0:
        name, version = s[:idx], s[idx + 1:]
        hit = _known_hit("npm", name, version, f"{name}@{version}")
        if hit is not None:
            hits.append(hit)
    hit = _py_known(cand)
    if hit is not None:
        hits.append(hit)
    return hits + _artifact(cand)


def _backstop(argv: list[str]) -> list[_Hit]:
    """Scan every argv string, split into pieces on whitespace, quotes and ; & | ( ) { }.
    Each piece, each comma part of it, and each run of two or three adjacent pieces from the
    SAME argv string (for "name (==V)" or "name == V") is checked as an npm spec, as a PEP 508
    requirement and as a package file name, raw and with shell escapes removed. Only known_bad
    hits come out."""
    cands: dict[str, None] = {}

    def add(text: str) -> None:
        for form in (text, _unescaped(text)):
            if form:
                for v in _variants(form):
                    cands.setdefault(v, None)

    for arg in argv:
        pieces = _pieces(arg)
        if len(pieces) > 1:
            add(arg.strip())  # a whole string such as "postmark-mcp@>=0 1.0.16"
        for i, piece in enumerate(pieces):
            add(piece)
            if "," in piece:
                for part in _split_commas(piece):
                    add(part)
            for n in (2, 3):
                if i + n <= len(pieces):
                    add("".join(pieces[i:i + n]))
    hits: list[_Hit] = []
    for cand in cands:
        hits += _scan_candidate(cand)
    return hits


def _combine(hits: list[_Hit]) -> list[Finding]:
    """One known_bad per package and version. Other package findings for a package that is
    known bad are dropped. Hits with no package (unparsed, digest, hashes) are kept."""
    bad_pkgs = {h.pkg for h in hits if h.finding.kind == "known_bad"}
    seen: set[tuple] = set()
    out: list[Finding] = []
    for h in hits:
        if h.finding.kind == "known_bad":
            key = (h.pkg, h.version)
            if key in seen:
                continue
            seen.add(key)
        elif h.pkg is not None and h.pkg in bad_pkgs:
            continue
        out.append(h.finding)
    return out


def lint_command(argv: list[str]) -> list[Finding]:
    """Install findings for one launch command given as an argv list. Never raises."""
    args = list(argv)
    hits = _lint(args, 0) + _backstop(args)
    # An unknown prefix wrapper (sudo, timeout 10, op run --, wsl...) hides the launcher from the
    # parser, so try it again from each later position and keep only known-bad results.
    for i in range(1, min(len(args), _MAX_OFFSET + 1)):
        hits += [h for h in _lint(args[i:], 0) if h.finding.kind == "known_bad"]
    return _combine(hits)


# --- client config files ------------------------------------------------------

def remote_origin(url: str) -> str:
    """Only the scheme and host of a URL, for display."""
    from urllib.parse import urlsplit

    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
    except ValueError:
        return "?"
    if parts.scheme:
        return f"{parts.scheme}://{host or '?'}"
    return host or "?"


def _strip_jsonc(text: str) -> str:
    """Remove // and /* */ comments and trailing commas before } or ], outside JSON strings."""
    out: list[str] = []
    i, n = 0, len(text)
    in_str = False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
        elif c == '"':
            in_str = True
            out.append(c)
            i += 1
        elif c == "/" and text.startswith("//", i):
            end = text.find("\n", i)
            i = n if end < 0 else end
        elif c == "/" and text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end < 0 else end + 2
        else:
            out.append(c)
            i += 1
    stripped = "".join(out)
    out = []
    i, n = 0, len(stripped)
    in_str = False
    while i < n:
        c = stripped[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(stripped[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
        elif c == ",":
            j = i + 1
            while j < n and stripped[j] in " \t\r\n":
                j += 1
            if j < n and stripped[j] in "}]":
                i += 1
                continue
        out.append(c)
        i += 1
    return "".join(out)


def _config_server(name: str, entry: object) -> ConfigServer:
    def unreadable(reason: str) -> ConfigServer:
        return ConfigServer(name=name, argv=None, url=None, reason=reason)

    if not isinstance(entry, dict):
        return unreadable("the entry is not an object")
    command = entry.get("command")
    if command is not None:
        if not isinstance(command, str):
            return unreadable("command is not a string")
        args = entry.get("args", [])
        if args is None:
            args = []
        if not (isinstance(args, list) and all(isinstance(a, str) for a in args)):
            return unreadable("args is not a list of strings")
        return ConfigServer(name=name, argv=[command, *args], url=None)
    url = entry.get("url")
    if isinstance(url, str):
        return ConfigServer(name=name, argv=None, url=url)
    return unreadable("it has neither a command nor a url")


def load_client_config(path: str) -> list[ConfigServer]:
    """Servers from an MCP client config file. Env values are never read or kept.

    Reads ``mcpServers`` (Claude Desktop, Claude Code .mcp.json, Cursor), ``servers``
    (VS Code .vscode/mcp.json), ``mcp.servers`` (VS Code settings.json) and
    ``projects.<path>.mcpServers`` (Claude Code ~/.claude.json, named ``<path>:<name>``).
    Accepts a UTF-8 BOM and JSON with comments and trailing commas. Raises OSError or
    ValueError on bad input.
    """
    with open(path, encoding="utf-8-sig") as fh:
        text = fh.read()
    data = json.loads(_strip_jsonc(text))
    if not isinstance(data, dict):
        raise ValueError("not a JSON object")
    maps: list[tuple[str, dict]] = []
    for key in ("mcpServers", "servers"):
        if isinstance(data.get(key), dict):
            maps.append(("", data[key]))
    mcp = data.get("mcp")
    if isinstance(mcp, dict) and isinstance(mcp.get("servers"), dict):
        maps.append(("", mcp["servers"]))
    projects = data.get("projects")
    if isinstance(projects, dict):
        for project, cfg in projects.items():
            if isinstance(cfg, dict) and isinstance(cfg.get("mcpServers"), dict):
                maps.append((f"{project}:", cfg["mcpServers"]))
    if not maps:
        raise ValueError('no MCP server map found (expected "mcpServers", "servers", '
                         '"mcp.servers" or "projects.<path>.mcpServers")')
    return [_config_server(prefix + name, entry) for prefix, smap in maps for name, entry in smap.items()]
