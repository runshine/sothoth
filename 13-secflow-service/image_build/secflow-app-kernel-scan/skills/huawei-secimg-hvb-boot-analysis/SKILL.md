---
name: huawei-secimg-hvb-boot-analysis
description: Analyze Huawei secimg/HVB-wrapped boot images to distinguish certificate chains, encrypted payloads, and footer metadata, and determine whether kernel recovery is possible from the image alone.
---

Use this skill when a file named boot.img (or similar partition image) does not look like a standard Android boot image and may instead be a Huawei secure image with certificate chain and encrypted payload.

Goals
- Determine whether the image is a normal Android boot image, compressed kernel blob, or Huawei secimg/HVB secure container.
- Identify certificate chain boundaries, payload start/end, and footer metadata.
- Prove whether the payload is encrypted by correlating high-entropy regions with metadata and cert extensions.
- Avoid wasting time trying random decompression on data that is clearly device-side encrypted.

Workflow

1. Initial triage
- Run:
  - `file IMAGE`
  - `sha256sum IMAGE`
  - `wc -c IMAGE`
- Inspect first bytes:
  - Python: read first 64 bytes and print hex
  - If header begins with `30 82 ...`, suspect DER/ASN.1 rather than Android boot magic.
- Optional probes:
  - `openssl asn1parse -inform DER -in IMAGE | head -n 120`
  - `strings -a -n 8 IMAGE | head`

2. Confirm DER certificate chain at front
- Parse consecutive DER objects from offset 0.
- A simple DER-length parser for SEQUENCE is enough to identify chained cert blobs.
- In the observed Huawei layout, there were 3 consecutive DER certs at the start.
- Extract and inspect with:
  - `openssl x509 -inform DER -in cert.der -noout -text`
  - or `openssl asn1parse` when x509 text decoding is incomplete.
- Look for issuer/subject strings like:
  - `Huawei Signature Center`
  - `secimg level1 cert`
  - `secimg level2 cert`
  - `secimg level3 cert`

3. Find alignment padding and true payload start
- Do not assume payload starts at 0x1000.
- After the DER chain, scan forward for the first non-zero byte.
- In the observed sample:
  - cert chain ended at `0x14a0`
  - zero padding continued until `0x2000`
  - encrypted payload started at `0x2000`
- Verify with short hexdumps around the transition.

4. Measure entropy to distinguish encryption from compression
- Compute per-page or per-megabyte Shannon entropy.
- Interpretation:
  - ~7.99 bits/byte across large contiguous regions strongly suggests encryption.
  - compressed kernels often have recognizable headers or mixed-entropy regions; full-range near-max entropy is a strong indicator of ciphertext.
- Also check for repeated zero-filled trailing space to find the effective end of meaningful data.

5. Identify payload length from cert extensions
- Parse the leaf cert with `openssl asn1parse`.
- Huawei samples use many private OIDs (`2.20.2.*` in the observed sample).
- Decode extension OCTET STRINGs manually when needed.
- Valuable fields found in the observed case:
  - partition name fields containing ASCII `boot`
  - integer fields with payload length, e.g. `0x2007000`
  - hash fields with 32-byte digests
- Correlate these against actual segments of the image.

6. Validate the encrypted payload cryptographically
- Extract candidate payload region and compute SHA-256.
- Compare against 32-byte private OID values from the leaf cert.
- In the observed sample:
  - payload = bytes `[0x2000 : 0x2009000)`
  - payload length = `0x2007000`
  - payload SHA-256 exactly matched private OID `2.20.2.65`
- This is strong evidence that the cert binds the encrypted payload, not plaintext kernel contents.

7. Locate HVB metadata/footer
- Search for `HVB\x00` in the image.
- In the observed sample:
  - main HVB structure at `0x2009000`
  - small trailing HVB footer near the last non-zero bytes
- Dump and inspect the first 256 bytes in hex.
- Expect fields that reference payload offsets/sizes and partition name; do not assume the footer contains a decryptable key blob.

8. Practical decision point: can plaintext kernel be recovered from this image alone?
- Usually no, if all of the following are true:
  - front matter is Huawei secimg certificate chain
  - payload region is uniformly near-max entropy
  - cert private OIDs bind the ciphertext hash/length
  - metadata is HVB-style footer/header rather than a standard compressed kernel
- Conclude the image is a secure container for device-side decryption/verification.
- Do not continue brute-forcing decompression formats unless there is evidence of a transform layer before encryption.

9. Next-step guidance for actual decryption efforts
- Pivot to reversing the loader chain, not the boot image itself.
- Highest-value binaries/partitions to obtain:
  - xloader / bootloader / fastboot
  - BL31 / BL32 / trustzone / TEE
  - any secimg/HVB verification code paths
- Reverse for:
  - decrypt function entrypoints
  - key ladder or hardware-bound key derivation
  - AES mode, IV/tag handling, and payload chunking
  - certificate/OID parsing logic mapping private fields to runtime structures

Observed Huawei sample mapping
- certs at offsets:
  - `0x00000000`, len `1954`
  - `0x000007a2`, len `1484`
  - `0x00000d6e`, len `1842`
- cert chain total: `0x14a0`
- zero pad after certs: `0xb60`
- encrypted payload start: `0x2000`
- encrypted payload length: `0x2007000`
- HVB metadata start: `0x2009000`
- private OID `2.20.2.65` matched payload SHA-256 exactly
- private OIDs `2.20.2.67` and `2.20.2.69` decoded to payload length `33583104` (`0x2007000`)

Pitfalls
- `file` may misleadingly report the whole image as a certificate because the image begins with DER.
- `openssl x509 -text` may decode some certs but not all leaf/private-extension structures cleanly; fall back to `openssl asn1parse`.
- Random `gzip`/`bzip2`/`MZ` hits inside ciphertext are normal false positives; do not overinterpret them.
- Do not assume all non-zero bytes are payload; Huawei images may include cert chain, alignment padding, encrypted payload, HVB metadata, and then zero-filled tail.

Verification checklist
- [ ] Confirm front DER cert chain exists
- [ ] Identify first non-zero byte after cert+padding
- [ ] Measure high entropy over candidate payload region
- [ ] Find HVB marker(s)
- [ ] Correlate payload size from cert OIDs with actual offsets
- [ ] Correlate payload SHA-256 with a cert OID hash field
- [ ] Only then conclude the image is encrypted and not recoverable from the image alone
