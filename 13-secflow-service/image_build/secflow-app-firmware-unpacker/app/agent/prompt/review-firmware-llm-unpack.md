Start to review the unpacking results of the firmware in $input, the unpacking results are saved in $output.

This is the LLM-stage review.
You must read both of the following review artifacts for this stage:
- `$output/summary.md` (or `$output/summary.txt` if needed), which records the current LLM unpack round summary
- `recursive_expand_manifest.json` from the current LLM-stage round context if it exists, which records the recursive expansion results after the current LLM unpack round
Use both the unpack summary and the recursive expansion manifest to judge whether the current LLM unpack round has fully and correctly unpacked the firmware.

Your final response must be a single-line JSON object only, with no extra prose:
- success: {"result":"success"}
- fail: {"result":"fail","reason":"$output/reason.md"}
