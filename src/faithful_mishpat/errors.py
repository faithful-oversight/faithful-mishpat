# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Exceptions raised by mishpat.

The classes come from faithful-core. ``MishpatError`` is its ``FaithfulError``, so
one ``except MishpatError`` also catches an error raised inside the library.
"""

from faithful_core.errors import (
    CollectionError,
    FaithfulError,
    InputError,
    OutputError,
    UsageError,
)

__all__ = [
    "CollectionError",
    "InputError",
    "MishpatError",
    "OutputError",
    "UsageError",
]

MishpatError = FaithfulError
"""Base class for errors mishpat reports to the user."""
