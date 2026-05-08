---
name: cc-00000000-lzma-compressed-data-properties unpack
description: Fast active skill for Huawei S6730 .cc firmware with SquashFS/uImage payloads
format_id: cc-00000000-lzma-compressed-data-properties
extensions: .cc
magic_hex: 00000000
keywords: firmware, unpack, huawei, s6730, squashfs, uimage
binwalk_sigs: lzma compressed data, squashfs filesystem, uimage header, 7-zip archive data
skill_status: active
skill_version: 1
family_id: cc-00000000-lzma-compressed-data-properties
promotion_success_count: 5
promotion_threshold: 5
source_run_id: fd27a3794e5c40619b020bc14808c17c
source_node_id: generic_executor
evaluation_batch: 
tools: file, binwalk, dd, unsquashfs, 7z, strings
---

Use this skill for Huawei S6730 `.cc` firmware images with magic `00000000` and the observed LZMA/SquashFS/uImage signatures.

Fast extraction procedure:
1. Create `$output/artifacts` and `$output/binwalk_extract`.
2. Run `binwalk "$firmware" > "$output/binwalk.txt"`. Inspect only bounded excerpts with `grep ... | head` or `sed -n`.
3. Extract only these known high-value components with byte-accurate large-block `dd`:
   - main xz SquashFS: offset 41668, size 123581704, output `$output/artifacts/rootfs_xz.squashfs`
   - gzip SquashFS 1: offset 123648804, size 8111913, output `$output/artifacts/rootfs_gzip1.squashfs`
   - gzip SquashFS 2: offset 135199940, size 7491332, output `$output/artifacts/rootfs_gzip2.squashfs`
   - Linux uImage kernel: offset 142746844, size 2524096, output `$output/artifacts/uImage_kernel`
   - uImage ramdisk: offset 145271292, size 9589941, output `$output/artifacts/uImage_ramdisk`
   Use `bs=4M iflag=skip_bytes,count_bytes status=none`; never use `bs=1` for these payloads.
4. Optionally copy one or two small obvious files from already extracted archives only if cheap. Do not recursively extract all nested blobs.
5. Write `$output/summary.txt` listing offsets, sizes, commands, and artifact paths. Once summary.txt is non-empty, stop immediately and print `AGENTFLOW_SKILL_DONE`.

Hard constraints:
- Do not use `binwalk -eM` or `binwalk -e -M`.
- Do not recursively copy or expand the full `$output/binwalk_extract` tree.
- Do not perform vulnerability analysis, disassembly, or broad reverse engineering.
