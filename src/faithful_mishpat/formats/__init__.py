# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Readers for the files mishpat compares.

Each module reads one kind of input into :mod:`faithful_mishpat.model` objects. XML is parsed
with ``faithful_core.xmlsafe``, which is safe for untrusted files:

* :mod:`~faithful_mishpat.formats.report`: ``Get-GPOReport -ReportType Xml`` files.
* :mod:`~faithful_mishpat.formats.registrypol`: ``Registry.pol`` files.
* :mod:`~faithful_mishpat.formats.backup`: ``Backup-GPO`` folders.
* :mod:`~faithful_mishpat.formats.bundle`: the mishpat export bundle.

:func:`faithful_mishpat.inputs.read_side` picks the reader from the input's content.
"""
