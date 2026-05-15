Review the current tool-based unpacking result.

Firmware input:
$input

Evolution output directory:
$output

Assess whether the selected tool has fully unpacked the firmware.

Requirements:
1. Read `$output/summary.txt` first. If it does not exist, read `$output/summary.md`.
2. Inspect the unpacked output tree and compare it against the firmware structure.
3. Determine whether the unpacking is complete enough to be accepted.
4. If it is not complete, identify what is missing or incorrect.
5. Even if the unpacking is mostly complete, assess whether the tool can still be improved, whether unpacking can be faster, and whether token usage can be lower.

When finished:
- If accepted, output exactly:
`{"result":"success"}`
- If rejected, write a detailed review to both `$output/reason.txt` and `$output/reason.md`, and output exactly:
`{"result":"fail","reason":"$output/reason.txt"}`
