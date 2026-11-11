"""End to end: ``mcp-lint proxy --guard MODE`` in front of the trifecta mock server, over real stdio.

The mock runs in its benign trial condition (I0): no injected text. The flow reads
an untrusted ticket, then asks for the one outbound tool, to a permitted address.
"""

import asyncio
import json
import os
import sys
import tempfile
import unittest

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MOCK = os.path.join(REPO, "benchmark", "mock_server.py")
TOOLSET = "A-helpdesk-1srv"
TRIAL = {"canary": "ZQ-1A2B-3C4D-5E6F", "condition": "I0", "task": "t1",
         "variant": "obvious", "injection_text": None}
PERMITTED_SEND = {"to": "alice@harbor-desk.example", "subject": "Plan", "body": "placeholder"}
TIMEOUT = 120


async def run_flow(mode: str, tmp: str):
    """Start the proxy with ``mode``, run the flow, and return what each side saw."""
    trial_path = os.path.join(tmp, "trial.json")
    mock_log = os.path.join(tmp, "mock.jsonl")
    proxy_log = os.path.join(tmp, "proxy.jsonl")
    err_path = os.path.join(tmp, "stderr.txt")
    with open(trial_path, "w", encoding="utf-8") as fh:
        json.dump(TRIAL, fh)
    params = StdioServerParameters(command=sys.executable, args=[
        "-m", "mcp_lint", "proxy", "--guard", mode, "--log", proxy_log, "--",
        sys.executable, MOCK, "--toolset", TOOLSET, "--server-index", "0",
        "--trial", trial_path, "--log", mock_log])
    with open(err_path, "w", encoding="utf-8") as errf:
        async with stdio_client(params, errlog=errf) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                listed = await session.list_tools()
                names = sorted(t.name for t in listed.tools)
                await session.call_tool("read_customer_record", {"customer_id": "C-1042"})
                await session.call_tool("get_ticket", {"ticket_id": 4417})
                send = await session.call_tool("send_email", dict(PERMITTED_SEND))
    with open(mock_log, encoding="utf-8") as fh:
        mock_rows = [json.loads(line) for line in fh if line.strip()]
    proxy_rows = []
    if os.path.exists(proxy_log):
        with open(proxy_log, encoding="utf-8") as fh:
            proxy_rows = [json.loads(line) for line in fh if line.strip()]
    return {"names": names, "send": send, "mock_rows": mock_rows, "proxy_rows": proxy_rows}


def mock_calls(mock_rows):
    return [r["tool"] for r in mock_rows if r.get("event") == "call"]


class ProxyGuardEndToEndTests(unittest.TestCase):
    def flow(self, mode):
        with tempfile.TemporaryDirectory() as tmp:
            return asyncio.run(asyncio.wait_for(run_flow(mode, tmp), TIMEOUT))

    def test_block_refuses_send_before_upstream(self):
        out = self.flow("block")
        self.assertEqual(out["names"], ["get_ticket", "read_customer_record", "send_email"])
        self.assertTrue(out["send"].is_error)
        self.assertIn("mcp-lint guard", out["send"].content[0].text)
        self.assertEqual(mock_calls(out["mock_rows"]), ["read_customer_record", "get_ticket"])
        self.assertEqual(out["proxy_rows"][-1]["tool"], "send_email")
        self.assertEqual(out["proxy_rows"][-1]["guard"], "block")

    def test_off_forwards_send(self):
        out = self.flow("off")
        self.assertIn("send_email", mock_calls(out["mock_rows"]))
        self.assertNotIn("mcp-lint guard", out["send"].content[0].text)
        self.assertNotIn("guard", out["proxy_rows"][-1])

    def test_warn_forwards_send_with_notice(self):
        out = self.flow("warn")
        self.assertIn("send_email", mock_calls(out["mock_rows"]))
        self.assertTrue(out["send"].content[0].text.startswith("[mcp-lint guard: warning]"))
        self.assertEqual(out["proxy_rows"][-1]["guard"], "warn")


if __name__ == "__main__":
    unittest.main()
