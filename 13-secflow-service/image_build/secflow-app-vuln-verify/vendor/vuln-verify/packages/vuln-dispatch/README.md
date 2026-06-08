# Router

Router is a deterministic Python 3.11+ CLI tool for vulnerability report routing.

It parses Markdown vulnerability reports, deduplicates reports by fingerprint, groups remaining reports by file and function, and assembles verifier context packages.

## Install

```bash
python -m pip install -e .
```

## CLI

```bash
vuln-dispatch \
  --reports /path/to/reports \
  --source-root /path/to/source \
  --binary-root /path/to/binaries \
  --threat /path/to/threat_model.md \
  --output /path/to/output \
  --logfile /path/to/vuln-dispatch_summary.json
```

## Output

The output directory contains:

- `threat_model.md`
- `routing_log.json`
- `groups/<group_id>/manifest.yaml`
- `groups/<group_id>/reports/*.md`
- `unrouteable/*.md`

## Development

The project uses only the Python standard library at runtime.

Run tests with pytest:

```bash
python -m pytest tests -v
```
