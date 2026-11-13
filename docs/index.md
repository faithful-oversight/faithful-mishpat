# mishpat documentation

mishpat compares two versions of Group Policy, one GPO or a whole domain, and writes a reviewable difference with the links, filters, and inheritance around it. It says what it could not compare, and it never claims more than the inputs support.

## Start here

- [Quickstart](quickstart.md): install mishpat and run the synthetic example in five minutes.
- [Collecting exports](collecting.md): run the exporter on a computer with RSAT, or collect remotely.
- [Command reference](usage.md): every command, option, and exit code, plus pipeline examples.
- [Input formats](formats.md): the three kinds of input and what each one records.
- [Reports and output](output.md): the report sections, the kinds of difference, and the output formats.
- [Limitations](limitations.md): what mishpat cannot do.

## Design

- [Architecture](architecture.md): how the tool is built and the rules the design follows.
- [Threat model](threat-model.md): what the tool protects, the threats, and the controls.
- [Releasing](releasing.md): how releases are made and verified.
- [Architecture decision records](adr/index.md): significant decisions and the reasons for them.
