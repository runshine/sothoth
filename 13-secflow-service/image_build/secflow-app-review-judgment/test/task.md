# Vulnerability Hunting Task

## Target
Entry function: `IPSEC_SOCKI_PipeMsg` with 61 tracked callees.

## Input
- Dataflow analysis: `/home/icsl/sothoth/13-secflow-service/image_build/secflow-app-review-judgment/test/dataflows`
- Source code: `/home/icsl/sothoth/13-secflow-service/image_build/secflow-app-review-judgment/test/source` (libipsec.c, libipsec.h, libipsec.asm)

## Requirements
1. Read final_report.md to understand the call chain
2. Read per-function dataflow reports in dataflow/
3. Verify taint paths against actual source code
4. Write confirmed vulnerability reports to results/result_NNN.md
5. Provide full evidence chains from taint source to dangerous sink
