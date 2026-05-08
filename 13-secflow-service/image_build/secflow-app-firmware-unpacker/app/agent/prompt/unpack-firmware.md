---
description: Start a firmware unpacking task with specified input and output directories
---
Use the firmware-unpacker agent to unpack the firmware in $input, and save all extracted results to $output.
Always create $output/summary.txt before finishing, even if no extractable components are found. If nothing can be extracted, document that clearly in the summary and stop.
