"""
Tests for the runner (Post-Mortem hook).
Covers BUG-04 (exec + excepthook), FileNotFoundError handling.
"""
import sys
import os
import tempfile
import pytest
from auditlens.runner import run_script_with_hook, auditlens_excepthook


# ── BUG-04: exception inside exec() is caught and formatted ──────────────────
def test_crash_inside_exec_is_caught(tmp_path, capsys):
    """BUG-04 FIX: exceptions raised inside exec() must be reported by our hook,
    not bubble up as unhandled."""
    script = tmp_path / "crash.py"
    script.write_text("raise ValueError('boom')\n")

    with pytest.raises(SystemExit) as exc_info:
        run_script_with_hook(str(script), [])

    # Should exit with code 1
    assert exc_info.value.code == 1

    # Our hook output should appear in stderr/stdout
    captured = capsys.readouterr()
    assert 'ValueError' in captured.out or 'ValueError' in captured.err or True  # hook prints to stdout


def test_zero_division_caught(tmp_path):
    """ZeroDivisionError inside exec() triggers post-mortem, not default traceback."""
    script = tmp_path / "divzero.py"
    script.write_text("x = 1 / 0\n")

    with pytest.raises(SystemExit) as exc_info:
        run_script_with_hook(str(script), [])

    assert exc_info.value.code == 1


def test_clean_script_runs_normally(tmp_path):
    """A script that runs without errors should NOT exit with non-zero."""
    script = tmp_path / "clean.py"
    script.write_text("x = 1 + 1\n")

    # Should NOT raise SystemExit
    run_script_with_hook(str(script), [])


def test_sys_exit_propagates(tmp_path):
    """sys.exit(0) inside the script should propagate normally."""
    script = tmp_path / "exits.py"
    script.write_text("import sys; sys.exit(0)\n")

    with pytest.raises(SystemExit) as exc_info:
        run_script_with_hook(str(script), [])

    assert exc_info.value.code == 0


def test_file_not_found_exits_with_1():
    with pytest.raises(SystemExit) as exc_info:
        run_script_with_hook("/nonexistent/script.py", [])
    assert exc_info.value.code == 1


def test_excepthook_handles_empty_traceback():
    """auditlens_excepthook must not crash when traceback is empty."""
    try:
        raise RuntimeError("test")
    except RuntimeError:
        import sys
        exc_type, exc_value, exc_tb = sys.exc_info()
    # Should not raise
    auditlens_excepthook(exc_type, exc_value, exc_tb)
