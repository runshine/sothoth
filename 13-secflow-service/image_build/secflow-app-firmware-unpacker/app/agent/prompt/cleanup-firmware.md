---
description: Clean up firmware extraction output directories by removing incomplete extraction intermediates and duplicate files
---
Use the firmware-extract-cleanup agent to cleanup the incomplete extraction intermediates and duplicate files in $input

Priority reminder:
- Treat large offset-named `.zlib` files such as `6D65AD4.zlib` as high-priority redundant cleanup candidates when they were likely produced by `binwalk -e --dd` and structured extraction results already exist elsewhere in the output tree.
