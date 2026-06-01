Use only an existing firmware unpacking Python tool from `$tools`.

Firmware input:
$input

Evolution output directory:
$output

Working Python tool file:
$working_tool

Target rules:
1. First inspect `$tools` and `$working_tool`.
2. Select the most appropriate existing tool. The preferred target is the provided working tool file.
3. Execute the Python tool workflow against `$input`, writing extraction results into `$output`.
4. Do not manually unpack the firmware outside the tool workflow.
5. After the selected Python tool finishes, stop. Do not run extra unpacking or post-processing commands outside the tool itself, including direct `unsquashfs`, `dd`, `cp`, `tar`, `rsync`, or other ad-hoc extraction/copy workflows against firmware contents.
6. Write `$output/summary.txt` and sync the same content to `$output/summary.md`, describing:
   - which tool was used
   - major commands/steps executed
   - extracted artifacts
   - remaining failures or suspicious gaps
   - unpacking time consumed
