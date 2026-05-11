import sys
import traceback

def auditlens_excepthook(exc_type, exc_value, exc_traceback):
    """
    Post-Mortem injector for CLI mode.
    Formats unhandled exceptions with forensic context.
    """
    tb_list = traceback.extract_tb(exc_traceback)
    if not tb_list:
        traceback.print_exception(exc_type, exc_value, exc_traceback)
        return

    last_frame = tb_list[-1]

    print("\n" + "=" * 80)
    print("\033[91m[AuditLens] CRASH DETECTED — Post-Mortem Diagnostics\033[0m")
    print("=" * 80)

    print(f"\n\033[1mLocation:\033[0m")
    print(f"   File:     \033[93m{last_frame.filename}\033[0m")
    print(f"   Line:     \033[93m{last_frame.lineno}\033[0m")
    print(f"   Function: \033[93m{last_frame.name}\033[0m")

    print(f"\n\033[1mError:\033[0m")
    print(f"   \033[91m{exc_type.__name__}: {exc_value}\033[0m")

    print(f"\n\033[1mCode Context:\033[0m")
    # Show ±2 lines of context from the file
    try:
        with open(last_frame.filename, 'r', encoding='utf-8') as fh:
            lines = fh.readlines()
        idx = last_frame.lineno - 1
        start = max(0, idx - 2)
        end = min(len(lines), idx + 3)
        for i in range(start, end):
            prefix = ">> " if i == idx else "   "
            color = "\033[91m" if i == idx else "\033[90m"
            print(f"   {color}{prefix}{i + 1}: {lines[i].rstrip()}\033[0m")
    except Exception:
        if last_frame.line:
            print(f"   \033[96m>> {last_frame.lineno}: {last_frame.line}\033[0m")

    print(f"\n\033[1mFull Traceback:\033[0m")
    traceback.print_exception(exc_type, exc_value, exc_traceback)
    print("=" * 80 + "\n")


def run_script_with_hook(script_path: str, extra_args: list):
    """
    BUG-04 FIX: sys.excepthook is NOT called for exceptions raised inside exec().
    We wrap the exec() in a try/except and call our hook manually.
    """
    print(f"\033[94m[AuditLens]\033[0m Running {script_path} with Post-Mortem hook...\n")

    sys.argv = [script_path] + list(extra_args)

    try:
        with open(script_path, 'r', encoding='utf-8') as f:
            source = f.read()
    except FileNotFoundError:
        print(f"\033[91m[ERROR]\033[0m Script not found: {script_path}")
        sys.exit(1)
    except OSError as e:
        print(f"\033[91m[ERROR]\033[0m Cannot read script: {e}")
        sys.exit(1)

    try:
        code = compile(source, script_path, 'exec')
        exec(code, {"__name__": "__main__"})  # noqa: S102
    except SystemExit:
        # Let the script's sys.exit() propagate normally
        raise
    except Exception:
        # BUG-04 FIX: manually invoke the hook — excepthook is never called for
        # exceptions caught inside exec(), only for top-level interpreter exits.
        exc_type, exc_value, exc_tb = sys.exc_info()
        auditlens_excepthook(exc_type, exc_value, exc_tb)
        sys.exit(1)
