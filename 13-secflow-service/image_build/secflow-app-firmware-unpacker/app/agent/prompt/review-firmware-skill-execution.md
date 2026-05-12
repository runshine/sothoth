Review the current tool-based unpacking result.

Firmware input:
$input

Evolution output directory:
$output

Assess whether the selected tool has fully unpacked the firmware.

Requirements:
1. Read `$output/summary.md` first.
2. Inspect the unpacked output tree and compare it against the firmware structure.
3. Determine whether the unpacking is complete enough to be accepted.
4. If it is not complete, identify what is missing or incorrect.

When finished:
- If accepted, output exactly:
`{"result":"success"}`
- If rejected, write a detailed review to `$output/reason.md` and output exactly:
`{"result":"fail","reason":"$output/reason.md"}`

