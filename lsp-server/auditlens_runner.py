"""
AuditLens Post-Mortem Runner — VS Code IPC edition.
Wraps a user script and sends crash data to the VS Code extension via TCP.

Usage: python auditlens_runner.py <script.py> [args...]
"""
import sys
import os
import traceback
import json
import socket
import hashlib
import hmac

# Port for IPC with VS Code extension.
IPC_PORT = 9999

# SEC-02 FIX: shared secret for IPC authentication.
# The VS Code extension generates this token at startup and writes it to
# a temp file readable only by the current user.  The runner reads it here.
_TOKEN_FILE = os.path.join(
    os.environ.get('TMPDIR', '/tmp'),
    f'auditlens_ipc_{os.getuid() if hasattr(os, "getuid") else "token"}.key'
)


def _load_token() -> str:
    """Load the shared IPC auth token, or return empty string if unavailable."""
    try:
        with open(_TOKEN_FILE, 'r') as fh:
            return fh.read().strip()
    except OSError:
        return ''


def send_to_vscode(data: dict):
    """
    SEC-02/03 FIX: sign the payload with HMAC-SHA256 so the VS Code
    extension can reject unauthenticated messages.
    """
    token = _load_token()
    payload_bytes = json.dumps(data).encode('utf-8')

    if token:
        sig = hmac.new(token.encode(), payload_bytes, hashlib.sha256).hexdigest()
        envelope = json.dumps({'sig': sig, 'payload': data}) + '\n'
    else:
        envelope = json.dumps({'sig': '', 'payload': data}) + '\n'

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(3)
            s.connect(('localhost', IPC_PORT))
            # CQ-10 FIX: newline-delimited framing so the receiver handles
            # partial TCP reads correctly.
            s.sendall(envelope.encode('utf-8'))
    except (ConnectionRefusedError, OSError):
        print(
            "[AuditLens] Could not connect to VS Code IPC server. "
            "Is the extension running?"
        )


def auditlens_excepthook(exc_type, exc_value, exc_traceback):
    """
    BUG-04 FIX: called manually from the except block — not via sys.excepthook —
    because sys.excepthook is never triggered for exceptions raised inside exec().
    """
    print("=" * 60)
    print("[AuditLens] Crash detected — initiating Post-Mortem diagnostics...")
    print("=" * 60)

    traceback.print_exception(exc_type, exc_value, exc_traceback)

    tb_list = traceback.extract_tb(exc_traceback)
    if not tb_list:
        return

    last_frame = tb_list[-1]

    crash_data = {
        "type": "crash_report",
        "exception_type": exc_type.__name__,
        "exception_message": str(exc_value),
        "file": os.path.abspath(last_frame.filename),  # SEC-05 FIX: absolute path
        "line": last_frame.lineno,
        "function": last_frame.name,
        "code_context": last_frame.line or '',
    }

    send_to_vscode(crash_data)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python auditlens_runner.py <script.py> [args...]")
        sys.exit(1)

    target_script = os.path.abspath(sys.argv[1])

    # SEC-05 FIX: validate extension before executing
    if not target_script.endswith('.py'):
        print(f"[AuditLens] Error: only .py files are supported, got: {sys.argv[1]}")
        sys.exit(1)

    if not os.path.isfile(target_script):
        print(f"[AuditLens] Error: file not found: {target_script}")
        sys.exit(1)

    # Remove runner name from argv so the target script sees itself as __main__
    sys.argv = sys.argv[1:]

    try:
        with open(target_script, 'r', encoding='utf-8') as fh:
            source = fh.read()
    except OSError as e:
        print(f"[AuditLens] Cannot read script: {e}")
        sys.exit(1)

    try:
        code = compile(source, target_script, 'exec')
        exec(code, {"__name__": "__main__"})  # noqa: S102
    except SystemExit:
        raise
    except Exception:
        exc_type, exc_value, exc_tb = sys.exc_info()
        auditlens_excepthook(exc_type, exc_value, exc_tb)
        sys.exit(1)
