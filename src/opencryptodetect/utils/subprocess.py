"""Subprocess isolation utilities with strict timeouts."""

import subprocess

from opencryptodetect.core.exceptions import OCDError


def safe_run_command(
    args: list[str],
    timeout_seconds: float = 30.0,
    cwd: str | None = None,
) -> tuple[int, str, str]:
    """Execute command safely with timeout and return (returncode, stdout, stderr)."""
    try:
        proc = subprocess.run(
            args,
            cwd=cwd,
            timeout=timeout_seconds,
            capture_output=True,
            text=True,
            check=False,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        raise OCDError(
            f"Command '{' '.join(args[:3])}...' timed out after {timeout_seconds}s",
            code="SUBPROC-TIMEOUT",
        )
    except FileNotFoundError:
        raise OCDError(f"Executable not found: {args[0]}", code="SUBPROC-NOTFOUND")
    except Exception as e:
        raise OCDError(f"Subprocess failed: {e}", code="SUBPROC-ERR", details=str(e))
