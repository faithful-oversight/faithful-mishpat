# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Keep stored passwords out of reports while still noticing when they change.

Group Policy Preferences items can carry a ``cpassword`` attribute: a password encrypted
with a key Microsoft published, so anyone who sees it can read the password. mishpat never
shows it. A reader replaces the value with :func:`hide`, a keyed fingerprint whose key is
chosen at random for each run: two sides read in the same run compare equal exactly when
the stored values match, but the fingerprint means nothing outside that run, so it cannot
be used to test guesses. Before anything is written, :func:`conceal` replaces every
fingerprint with :data:`SHOWN`, so the reports stay the same from run to run.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import Any

PREFIX = "\x00mishpat-hidden:"
SHOWN = "(hidden stored password)"
NAMES = frozenset({"cpassword"})
_KEY = secrets.token_bytes(32)


def hide(value: str) -> str:
    """Return a stand-in for a stored password, or ``""`` when none is stored."""
    if not value:
        return ""
    return PREFIX + hmac.new(_KEY, value.encode("utf-8"), hashlib.sha256).hexdigest()


def is_hidden_name(name: str) -> bool:
    """Say whether an attribute name holds a stored password."""
    return name.lstrip("@").casefold() in NAMES


def conceal(value: Any) -> Any:
    """Return ``value`` with every stand-in replaced by :data:`SHOWN`."""
    if isinstance(value, str):
        return SHOWN if value.startswith(PREFIX) else value
    if isinstance(value, dict):
        return {k: conceal(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [conceal(v) for v in value]
    return value


def _stand_ins(value: Any, path: tuple[str, ...] = ()) -> set[tuple[tuple[str, ...], str]]:
    if isinstance(value, str):
        return {(path, value)} if value.startswith(PREFIX) else set()
    if isinstance(value, dict):
        return {f for k, v in value.items() for f in _stand_ins(v, (*path, str(k)))}
    if isinstance(value, list | tuple):
        return {f for i, v in enumerate(value) for f in _stand_ins(v, (*path, str(i)))}
    return set()


def password_changed(before: Any, after: Any) -> bool:
    """Say whether a stored password differs between two values, wherever it sits.

    A password present on one side only counts as a change; so does one that moved.
    """
    return _stand_ins(before) != _stand_ins(after)
