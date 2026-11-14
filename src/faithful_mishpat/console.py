# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Printing that cannot change an exit code that is already decided.

The reports are written before the closing summary is printed, so a failure to print
(a closed pipe, or a stream that cannot encode a character in a path) must never turn a
finished run into an internal error. Commands decide their exit code first, print through
:func:`say`, and let :func:`finish` flush at the end.
"""

from __future__ import annotations

import contextlib
import os
import sys
from typing import Any, TextIO

_STATE: dict[str, Any] = {"stdout_closed": False, "null": None}


def prepare() -> None:
    """Make the standard streams unable to fail on a character they cannot encode.

    A character that the stream's encoding cannot hold is written as a backslash escape
    instead of raising ``UnicodeEncodeError``. A stream that cannot be reconfigured is
    left as it is.
    """
    _STATE["stdout_closed"] = False
    if _STATE["null"] is not None:  # left by an earlier closed pipe in this process
        with contextlib.suppress(Exception):
            _STATE["null"].close()
        _STATE["null"] = None
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            with contextlib.suppress(Exception):
                reconfigure(errors="backslashreplace")


def stdout_closed() -> None:
    """Stop printing to standard output after a closed pipe.

    Standard output is pointed at the null device, as the Python documentation advises for
    ``SIGPIPE``, so that flushing at interpreter shutdown cannot raise a second time.
    """
    _STATE["stdout_closed"] = True
    with contextlib.suppress(Exception):
        null = os.open(os.devnull, os.O_WRONLY)
        try:
            os.dup2(null, sys.stdout.fileno())
        finally:
            os.close(null)
    with contextlib.suppress(Exception):
        _STATE["null"] = open(os.devnull, "w", encoding="utf-8")  # noqa: SIM115, PTH123 - lives until the process ends
        sys.stdout = _STATE["null"]


def _write(stream: TextIO, data: str) -> None:
    try:
        stream.write(data)
    except UnicodeEncodeError:
        # A stream that refused to be reconfigured: write what it can hold, escaped.
        stream.write(data.encode("ascii", "backslashreplace").decode("ascii"))


def say(text: str = "", *, err: bool = False, end: str = "\n") -> None:
    """Print ``text``, to standard error with ``err``. A closed pipe is never an error."""
    stream = sys.stderr if err else sys.stdout
    if not err and _STATE["stdout_closed"]:
        return
    try:
        _write(stream, text + end)
    except BrokenPipeError:
        if not err:
            stdout_closed()
    except (OSError, ValueError):
        # A closed or unwritable stream: the work is done and there is nowhere to say so.
        if not err:
            _STATE["stdout_closed"] = True


def finish() -> None:
    """Flush both streams; a closed pipe found now is handled like one found while printing."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.flush()
        except BrokenPipeError:
            if stream is sys.stdout:
                stdout_closed()
        except (OSError, ValueError):
            continue
