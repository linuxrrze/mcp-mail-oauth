"""Startup stays quiet: the Authlib httpx deprecation is silenced (D21)."""

import subprocess
import sys


def test_no_authlib_httpx_warning_on_import():
    result = subprocess.run(
        [sys.executable, "-W", "default", "-c", "import mcp_mail.server, mcp_mail.diagnose"],
        capture_output=True, text=True, check=True,
    )
    assert "httpx module is deprecated" not in result.stderr
