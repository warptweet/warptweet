#!/usr/bin/env python3
"""Signal one previously identified Linux process through a pidfd."""

from __future__ import annotations

import os
import re
import signal
import sys


EXIT_USAGE = 64
EXIT_UNAVAILABLE = 69
EXIT_IO_ERROR = 74
EXIT_GONE = 75
EXIT_IDENTITY_MISMATCH = 76
EXIT_PERMISSION = 77


def fail(message: str, status: int) -> int:
    print(f"pidfd signal: {message}", file=sys.stderr)
    return status


def process_identity(pid: int) -> str:
    process_directory = f"/proc/{pid}"
    directory_stat = os.stat(process_directory, follow_symlinks=False)
    with open(f"{process_directory}/stat", encoding="ascii") as stat_file:
        stat_text = stat_file.read()

    command_end = stat_text.rfind(") ")
    if command_end < 0:
        raise ValueError("process stat has no command terminator")
    fields_after_command = stat_text[command_end + 2 :].split()
    if len(fields_after_command) <= 19:
        raise ValueError("process stat omits the start time")
    start_time = fields_after_command[19]
    if not start_time.isdigit():
        raise ValueError("process start time is not numeric")
    return f"{directory_stat.st_dev}:{directory_stat.st_ino}:{start_time}"


def main(arguments: list[str]) -> int:
    if len(arguments) != 5:
        return fail(
            "usage: pidfd-signal.py PID DEVICE:INODE:START ABSOLUTE_EXECUTABLE TERM|KILL",
            EXIT_USAGE,
        )
    if sys.platform != "linux" or not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        return fail("Linux pidfd APIs are unavailable", EXIT_UNAVAILABLE)

    pid_text, expected_identity, expected_executable, signal_name = arguments[1:]
    if not pid_text.isdigit() or int(pid_text) <= 0:
        return fail("PID must be a positive decimal integer", EXIT_USAGE)
    if re.fullmatch(r"[0-9]+:[0-9]+:[0-9]+", expected_identity) is None:
        return fail("expected process identity is malformed", EXIT_USAGE)
    if not os.path.isabs(expected_executable) or os.path.normpath(expected_executable) != expected_executable:
        return fail("expected executable must be a clean absolute path", EXIT_USAGE)
    allowed_signals = {"TERM": signal.SIGTERM, "KILL": signal.SIGKILL}
    if signal_name not in allowed_signals:
        return fail("signal must be TERM or KILL", EXIT_USAGE)

    pid = int(pid_text)
    try:
        pidfd = os.pidfd_open(pid, 0)
    except ProcessLookupError:
        return fail("process no longer exists", EXIT_GONE)
    except PermissionError:
        return fail("permission denied opening pidfd", EXIT_PERMISSION)
    except OSError as error:
        return fail(f"cannot open pidfd: {error}", EXIT_IO_ERROR)

    try:
        try:
            actual_identity = process_identity(pid)
            actual_executable = os.path.realpath(f"/proc/{pid}/exe", strict=True)
        except (FileNotFoundError, ProcessLookupError):
            return fail("process exited during identity verification", EXIT_GONE)
        except (OSError, ValueError) as error:
            return fail(f"cannot verify process identity: {error}", EXIT_IO_ERROR)

        if actual_identity != expected_identity:
            return fail("process identity does not match the captured identity", EXIT_IDENTITY_MISMATCH)
        if actual_executable != expected_executable:
            return fail("process executable does not match the captured executable", EXIT_IDENTITY_MISMATCH)

        try:
            signal.pidfd_send_signal(pidfd, allowed_signals[signal_name], None, 0)
        except ProcessLookupError:
            return fail("process exited before signaling", EXIT_GONE)
        except PermissionError:
            return fail("permission denied signaling through pidfd", EXIT_PERMISSION)
        except OSError as error:
            return fail(f"cannot signal through pidfd: {error}", EXIT_IO_ERROR)
    finally:
        os.close(pidfd)

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
