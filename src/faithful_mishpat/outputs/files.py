# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Publish a set of report files together, privately, and without clobbering.

faithful-core does the work; its ``faithful_core.files`` module states every guarantee.
This module only names mishpat's temporary files: ``.mishpat-*.tmp`` while writing, and
``.mishpat-old-*.bak`` while a forced replace can still be undone.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from faithful_core import files as core

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path

SLUG = "mishpat"


def write_files(directory: Path, files: Mapping[str, str], *, force: bool) -> list[Path]:
    """Write every file, or leave ``directory`` as it was; see ``faithful_core.files``.

    Raises:
        OutputError: A target exists and ``force`` is false, a target is a directory, or
            writing fails.
    """
    return core.write_files(directory, files, force=force, slug=SLUG)
