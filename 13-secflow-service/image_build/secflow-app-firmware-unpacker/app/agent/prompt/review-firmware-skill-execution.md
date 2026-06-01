Review the current tool-based unpacking result.

Firmware input:
$input

Evolution output directory:
$output

Working Python tool file path:
$working_tool

Round context file:
$round_context

Assess whether the selected tool has fully unpacked the firmware, and whether the tool itself is acceptable as a reusable family-level Python unpacker.

Requirements:
1. Read `$round_context` first. Treat it as the primary context for this round.
2. Read `$output/summary.txt` first. If it does not exist, read `$output/summary.md`.
3. Read the current tool file at `$working_tool`.
4. Inspect the unpacked output tree and compare it against the firmware structure.
5. Determine whether the unpacking is complete enough to be accepted.
6. If it is not complete, identify what is missing or incorrect.
7. Even if the unpacking is mostly complete, assess whether the tool can still be improved and whether unpacking can be faster.
8. You must also review the tool implementation itself as part of the acceptance decision. Reject the round if the tool is only suitable for the current sample and not for the format family.
9. Do not read full session transcripts by default. Only if `$round_context`, the current tool, and the summary/reason files are insufficient, read `sessions/index.json` first and then open only one targeted session file.

Tool review checklist:
- Check whether the tool hardcodes task-specific runtime paths such as `/data/files/...`, project IDs, task IDs, or sample-specific absolute paths.
- Check whether the tool hardcodes a single sample filename or version string instead of deriving them from the current input.
- Check whether the tool relies only on fixed offsets/sizes with no family-level fallback such as header parsing, magic validation, bounded binwalk, signature discovery, or equivalent runtime detection.
- Check whether known offsets are used only as validated fast paths rather than the only extraction strategy.
- Check whether the tool reads large firmware files efficiently. Reject tools that perform unbounded whole-file reads for large inputs when seek/read(size) or chunked reads should be used.
- If the tool invokes `unsquashfs`, verify it uses container-safe flags such as `-no-xattrs`.
- Prefer family-level generality over case-by-case patches. If the tool is clearly tied to the current sample, reject it.

When finished:
- If accepted, output exactly:
`{"result":"success"}`
- If rejected, write a detailed review to both `$output/reason.txt` and `$output/reason.md`, and output exactly:
`{"result":"fail","reason":"$output/reason.txt"}`
