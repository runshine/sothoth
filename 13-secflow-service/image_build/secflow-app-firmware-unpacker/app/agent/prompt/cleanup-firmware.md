---
description: Clean up firmware extraction output directories by removing incomplete extraction intermediates and duplicate files
---
Use the firmware-extract-cleanup agent to cleanup the incomplete extraction intermediates and duplicate files in $input

This prompt is executed by the backend firmware unpacker service in non-interactive mode.
Do not ask the user for confirmation, options, exclusions, or approval.
Analyze the directory, execute safe cleanup directly, then report what was deleted, what was kept, and why.

Priority reminder:
- Treat large offset-named `.zlib` files such as `6D65AD4.zlib` as high-priority redundant cleanup candidates when they were likely produced by `binwalk -e --dd` and structured extraction results already exist elsewhere in the output tree.
