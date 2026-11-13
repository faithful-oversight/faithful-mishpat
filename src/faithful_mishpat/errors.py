# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Exceptions raised by mishpat."""


class MishpatError(Exception):
    """Base class for errors mishpat reports to the user."""


class InputError(MishpatError):
    """An input file or configuration cannot be read or has the wrong shape."""


class CollectionError(MishpatError):
    """Live collection could not connect, authenticate, or read what it needs."""


class UsageError(MishpatError):
    """The command's options do not fit together, so nothing was attempted."""
