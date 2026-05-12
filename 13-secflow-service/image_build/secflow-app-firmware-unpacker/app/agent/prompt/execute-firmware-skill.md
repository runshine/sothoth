Use only an existing firmware unpacking SKILL from `$tools`.

Firmware input:
$input

Evolution output directory:
$output

Working SKILL file:
$working_skill

Target rules:
1. First inspect `$tools` and `$working_skill`.
2. Select the most appropriate existing tool. The preferred target is the provided working skill.
3. Execute the tool workflow against `$input`, writing extraction results into `$output`.
4. Do not manually unpack the firmware outside the tool workflow.
5. Write `$output/summary.md` describing:
   - which tool was used
   - major commands/steps executed
   - extracted artifacts
   - remaining failures or suspicious gaps

