# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Argument types shared by the commands."""

from __future__ import annotations

import argparse
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable


def bounded(low: int, high: int, what: str) -> Callable[[str], int]:
    """Return an argument type that accepts a whole number from ``low`` to ``high``."""

    def check(text: str) -> int:
        if not text.isdigit() or not low <= int(text) <= high:
            msg = f"give {what} from {low} to {high}"
            raise argparse.ArgumentTypeError(msg)
        return int(text)

    check.__name__ = what
    return check
