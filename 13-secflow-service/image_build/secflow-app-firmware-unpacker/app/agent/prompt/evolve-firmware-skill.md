Improve the existing firmware unpacking tool.

Firmware input:
$input

Evolution output directory:
$output

Tools directory:
$tools

Main unpack task run directory:
$main_run

Current evolution job run directory:
$evolution_run

Working SKILL file path:
$working_skill

Rules:
1. Read the main unpack task sessions under `$main_run/sessions`.
2. Read the evolution-job sessions under `$evolution_run/sessions`.
3. Read the current working tool file at `$working_skill`.
4. Read `$output/summary.md` and `$output/reason.md` if present.
5. Improve the tool instructions so the next round can cover the gaps found by review.
6. Do not perform manual unpacking as a substitute for fixing the tool.
7. You may either modify `$working_skill` directly, or create a brand-new `.md` tool file under the same `working_skill/` directory.
8. Do not write tools directly into the formal tools repository path. Only write inside the current evolution job's `working_skill/` directory.

Your final response must contain only the absolute path of the updated tool file.
