"""Shim: the tagger lives in mcp_lint.trifecta (frozen for the benchmark)."""
import sys
from mcp_lint import trifecta as _trifecta
sys.modules[__name__] = _trifecta
