---
name: firmware-extract-cleanup
description: Clean up firmware extraction output directories by removing incomplete extraction intermediates and duplicate files. Works with binwalk or custom extraction tool outputs. Use when the user needs to clean up unpacking results, remove redundant files, or free disk space.
---

# Firmware Extraction Cleanup

## Goal

Analyze a firmware extraction output directory, identify and remove:
1. **Incomplete extraction intermediates** — archive files that have already been extracted but the original compressed files are still present
2. **Duplicate directories** — extraction subdirectories with highly overlapping content (e.g., duplicate initramfs for multiple board types)
3. **Duplicate files** — files with identical content appearing in multiple locations
4. **Extraction artifacts** — zero-byte files, empty directories, etc.
5. **Binwalk bulk-dd artifacts** — large `.zlib` files named by extraction offset, typically produced by `binwalk -e --dd`

## Workflow

**Follow these steps strictly in order. Complete each step before proceeding to the next. Analyze first, then clean automatically, then verify.**

### Step 1: Understand the Directory Structure

Connect to the target server and inspect the overall structure of the extraction output:

```bash
# List top-level contents
ls -la <extraction_dir>

# Show size of each first-level subdirectory
du -sh <extraction_dir>/*/

# Count total files
find <extraction_dir> -type f | wc -l

# Count files per top-level subdirectory
for d in <extraction_dir>/*/; do echo "$(find "$d" -type f | wc -l) $d"; done
```

### Step 2: Identify Incomplete Extraction Intermediates

Intermediate files are archive/compressed files whose contents have already been extracted elsewhere, but the archive itself was not removed.

**Search for all archive/compressed files:**

```bash
# Find all archive/compressed files
find <extraction_dir> -type f \( \
  -name "*.tar.gz" -o -name "*.tgz" -o -name "*.tar.bz2" -o \
  -name "*.tar.xz" -o -name "*.gz" -o -name "*.bz2" -o \
  -name "*.xz" -o -name "*.zip" -o -name "*.7z" -o \
  -name "*.cpio" -o -name "*.squashfs" -o -name "*.cramfs" -o \
  -name "*.img" -o -name "*.ext2" -o -name "*.ext3" -o -name "*.ext4" \
\)
```

**For each archive file found, determine whether it is an intermediate:**

- If the archive's contents have already been extracted into a sibling directory or another location (e.g., `xxx.tar.gz` has a corresponding `xxx/` directory nearby, or its contents exist in
`tar_extracted/`, `cpio_extracted/`, etc.), then it is an **intermediate file and can be deleted**
- If the archive is a runtime resource that the firmware itself ships (e.g., `.zip` YANG model files or `.tar.gz` link files inside a squashfs root — these are data the firmware uses at runtime), then it
**should NOT be deleted**

**Common intermediate file patterns (Huawei firmware):**

| Pattern | Description | Recommendation |
|---------|-------------|----------------|
| `rpglink*.tar.gz` inside `*_squashfs_root/` | RPG link archives, typically contain symlink manifests | Check if a corresponding extracted directory exists; if so, can delete |
| `dbupgrade.zip` inside squashfs | Database upgrade script package | Can delete if already extracted elsewhere |
| Top-level `.squashfs` / `.cpio` raw files | Intermediate archives extracted by binwalk | Can delete if corresponding `*_squashfs_root/` or `cpio_extracted/` exists |
| `.ext2` / `.ext3` filesystem images | Extracted filesystem images | Can delete if superblock is corrupt and contents are unrecoverable |
| `<HEX_OFFSET>.zlib` such as `6D65AD4.zlib` | Large zlib blobs emitted by `binwalk -e --dd` from embedded signatures | Treat as redundant extraction artifacts and prioritize deletion, especially when many such files exist and structured results already exist elsewhere |

**Special rule for offset-named `.zlib` blobs:**

- If a file matches the pattern `^[0-9A-Fa-f]{6,}\.zlib$`, especially when it is large and appears in batches, assume it is a binwalk bulk extraction artifact unless there is strong evidence that it is a deliberate firmware payload the user wants to preserve
- These files are usually generated from embedded zlib signatures after `binwalk -e --dd`, often overlap heavily, and often consume tens of GB without adding meaningful unpacking value
- If structured extraction results already exist, such as extracted squashfs/rootfs trees, these offset-named `.zlib` files should be listed as high-priority cleanup candidates

### Step 3: Identify Duplicate Directories

Firmware extraction often produces directories with highly overlapping content, such as:
- Multiple CPIO initramfs images (different board models but 95%+ identical files)
- Multiple TAR packages (different architectures but identical file trees)

**Compare file lists of similar directories:**

```bash
# Compare file lists of two directories
diff <(cd <dir_A> && find . -type f | sort) <(cd <dir_B> && find . -type f | sort)

# If differences are minimal, further compare file contents
diff <(cd <dir_A> && find . -type f -exec md5sum {} \; | sort -k2) \
    <(cd <dir_B> && find . -type f -exec md5sum {} \; | sort -k2) | head -30
```

**Decision criteria:**

- Two directories with **identical** file lists and **identical** file contents → keep one, delete the other
- Two directories with **highly similar** file lists (>90% overlap) but minor differences → they are variants for different boards/architectures; **recommend keeping** unless there is strong evidence they are redundant
- Two directories with **significant differences** → not duplicates, **keep both**

**Important caveats:**
- `x86_64` and `aarch64` architecture directories may look structurally similar but contain different binaries — **these are NOT true duplicates; do not delete**
- Only initramfs images of the same architecture for different board types may be true duplicates

### Step 4: Identify Duplicate Files

After confirming there are no duplicate directories, check for duplicate files across directories:

```bash
# Group files by size to find duplicate candidates (files with different sizes cannot be duplicates)
find <extraction_dir> -type f -not -empty -printf '%s %p\n' | sort -n | \
  awk '{if(size==$1){print prev; print $0} else {size=$1}; prev=$0}'

# Compute MD5 for candidate files to confirm true duplicates
# (run md5sum on the file paths from the previous step's output)
```

**Decision criteria:**

- Files with identical MD5 hashes are duplicates
- Keep the copy at the most "natural" path (prefer files under the main `squashfs_root` directory; treat copies in `cpio_extracted/` or `tar_extracted/` as secondary)
- **Do NOT delete** files with the same name under different architectures (they may have the same name but different binary content)

### Step 5: Check for Artifacts

```bash
# Find zero-byte files
find <extraction_dir> -type f -empty

# Find empty directories
find <extraction_dir> -type d -empty
```

Zero-byte files and empty directories are typically extraction leftovers and can be safely deleted.

### Step 6: Summarize Report and Execute

**Before performing any deletions, summarize the full cleanup plan in the response/log output, then execute it directly.**

Use this format:

```
═══════════════════════════════════════════════════
Firmware Extraction Cleanup Plan
═══════════════════════════════════════════════════
Target directory: <path>
Current file count: XXX
Current total size: XXX MB

1. Intermediate Files (N files, ~XX MB)
  - <file_path_1> (size)  Reason: corresponding extracted directory XXX exists
  - <file_path_2> (size)  Reason: ...

2. Duplicate Directories (N groups)
  - Keep:   <dir_A> (XX files)
    Delete: <dir_B> (XX files)  Similarity: XX%
    Reason: file lists and contents are identical

3. Duplicate Files (N groups, ~XX MB)
  - MD5: xxxx
    Keep:   <path_A>
    Delete: <path_B>, <path_C>

4. Artifacts
  - Zero-byte files: N
  - Empty directories: N

Estimated space savings: XX MB
═══════════════════════════════════════════════════
```

Do not ask follow-up questions or present cleanup options. This agent runs in a non-interactive backend task. After summarizing the plan, immediately execute the cleanup according to the safety rules in this document.

### Step 7: Execute Cleanup

Delete items one by one:

```bash
# Delete intermediate files
rm -f <file_path>

# Delete duplicate directories
rm -rf <dir_path>

# Delete duplicate files
rm -f <file_path>

# Clean up empty directories
find <extraction_dir> -type d -empty -delete

# Clean up zero-byte files
find <extraction_dir> -type f -empty -delete
```

Print a confirmation message after each deletion.

### Step 8: Verify

After cleanup is complete, re-scan and show results:

```bash
# File count after cleanup
find <extraction_dir> -type f | wc -l

# Total size after cleanup
du -sh <extraction_dir>
```

Present a before-and-after comparison to the user.

## Important Notes

1. **Analyze before deleting** — never skip the analysis steps and jump straight to deletion
2. **Non-interactive backend mode** — do not ask for confirmation, options, exclusions, or approval; execute the safe cleanup directly after analysis
3. **Architecture awareness** — x86_64 and aarch64 files are NOT duplicates even if they share the same name
4. **Firmware resource files** — `.zip`/`.tar.gz` files inside squashfs roots that are runtime resources (e.g., YANG models, config files) should not be treated as intermediates
5. **Signature files** — `.cms`, `.pss.cms`, `.crl` files are firmware signature verification files; keep them unless the user explicitly requests removal
6. **Offset-named `.zlib` blobs** — filenames like `6D65AD4.zlib` are normally binwalk extraction artifacts, not first-class unpack results; default to cleaning them unless explicitly preserved
7. **Remote operations** — if operating on a remote server via SSH, all shell commands must be executed through the SSH connection
