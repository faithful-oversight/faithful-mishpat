# 4. A JSON Lines export bundle with hashed files and a structure line

- Status: accepted
- Date: 2026-11-11

## Context

mishpat compares two versions of Group Policy. A `Backup-GPO` folder holds each GPO: its report, its core settings, and its `Registry.pol` files. It does not hold where the GPOs are linked in the directory, the order of the links, which organizational units block inheritance, or the query of each WMI filter. That context lives in Active Directory. The exporter has to collect both, with one script that runs on an administration workstation or on a domain controller, and that can run over PowerShell remoting with nothing copied to the controller.

The file it writes has to meet these needs:

- It must stream. The exporter cannot hold every GPO in memory, and `mishpat collect` receives the file as lines from a remoting session.
- It must carry each backup unchanged, so the same reader serves a backup folder and an export, and the exporter does not interpret Group Policy.
- It must show whether it is whole. An export that stops after three of forty GPOs must not look complete.
- It must show which file is damaged, not only that something is.
- It must carry the structure of the domain, which a backup lacks, and must record what the exporter could not read, so a failure is a gap in the comparison and not silence.
- It must be pure ASCII when the exporter writes it, because Windows PowerShell 5.1 reads and writes in the system code page.

Options considered:

- **A copy of the backup folders.** It keeps the files, but it cannot be streamed over a remoting session, has no place for the structure, the gaps, or a hash, and is many files to move and check.
- **A ZIP archive.** It cannot be sent as lines before it is complete, so a remote run would need a second transfer. It also has no place for the structure or gaps, and the path names in it need the same checks as any other.
- **One JSON document.** The reader must hold it whole, and a document cut short is not valid JSON, so everything in it is lost.
- **JSON with the settings already interpreted.** The exporter would have to read Group Policy XML in PowerShell, which makes two implementations of the same reading. mishpat keeps one: the Python readers.
- **JSON Lines with the files, a structure line, and a trailer.** Each line stands alone, so a cut file still yields every complete line.

## Decision

- The export bundle is JSON Lines in UTF-8, with `\n` line ends. It has one header line, one line for each file, one structure line, and one trailer line.
- The header starts, byte for byte, with `{"mishpat_export":`, so the format is detected from the first bytes and the filename does not matter. It names the collector and its version, the domain, when the export ran, and the scope: `"all"`, or the GUIDs that were asked for. A scope of `"all"` is how a reader knows the export is a whole domain, so a GPO that is missing from a later one was deleted.
- Each file line holds one file of a `Backup-GPO` folder: its path inside the bundle, its size, its SHA-256, and its bytes in base64. The reader checks the size and hash of each file, so damage is found in the file it hit.
- The structure line holds the scopes of management (the domain, every organizational unit, and every site, each with its raw `gPLink` and whether it blocks inheritance) and the WMI filters with their queries. The raw `gPLink` is kept as the directory states it. The reader parses it, so there is one place that knows the rules for link order.
- The structure line may hold `gaps`: each a `what` and a `reason`. The exporter records a part of the directory that it cannot read, and goes on. Each gap becomes a problem in the report.
- The trailer holds the number of file lines and the SHA-256 of every byte before it. The exporter writes it last.
- The exporter writes pure ASCII. It escapes every character outside printable ASCII as `\uXXXX`.
- The reader checks each line strictly and treats every fault as a problem: a repeated property name, `NaN`, an unpaired surrogate, nesting deeper than 8 levels, a path that is not a plain relative path, a size or hash that does not match, a missing or wrong trailer, and anything after the trailer. Only a bad first line stops the run. It uses every line that is fine. Limits cap a file at 64 MiB, a bundle at 100,000 files and 1 GiB, and a line at the size of the largest file in base64 plus its keys.
- The reader never writes a bundle's files to disk. It holds them in memory and reads them with the backup reader.
- The bundle follows a published, versioned JSON Schema, `export-v1.schema.json`. `mishpat schema export` prints it.
- The Python writer in `formats.bundle` exists for the bundled example and for tests. It is the reference for what the exporter emits. The exporter does not use it.

## Consequences

The reader streams, so a bundle's size is limited by the caps and not by the file. A file cut short by a full disk, a dropped connection, or a stopped script is detected, and every line before the cut is still used.

The bundle holds every file that `Backup-GPO` wrote, not only the files mishpat reads. It can hold more sensitive content than a report does. The documentation says to treat a bundle as sensitive.

Base64 makes the bundle a third larger than the files in it. Memory use while reading is the size of the files, up to the cap.

The PowerShell script and the Python reader are two implementations of one format. Tests keep them in step: the script's output is checked by an independent reader written in the tests, and by the real reader. A change to the shape needs a new schema version.

The hash detects a file that was cut short or damaged. It does not show who wrote the file, because anyone who edits it can compute the hash again. Authenticity stays the job of the system that stores the file. The [threat model](../threat-model.md) says so.

The exporter writes the lines to a temporary file and writes the trailer last. It moves the file to its final name only after the trailer is written, so a failed run leaves no file under that name. A file that is cut short in some other way has no trailer, which the reader reports. The remote collector adds a second check before it publishes the file. See [ADR 5](0005-remote-collection.md).
