Start to review the unpacking results of the firmware in $input, the unpacking results are saved in $output.

This is the tool-stage review.
You must first read `recursive_expand_manifest.json` from the current tool-stage round context if it exists, and use it as the primary recursive expansion evidence for this review.
You may also read `$output/summary.txt` or `$output/summary.md` as supporting context, but the recursive expansion manifest is the key review artifact for this stage.

Your final response must be a single-line JSON object only, with no extra prose:
- success: {"result":"success"}
- fail: {"result":"fail","reason":"$output/reason.md"}
