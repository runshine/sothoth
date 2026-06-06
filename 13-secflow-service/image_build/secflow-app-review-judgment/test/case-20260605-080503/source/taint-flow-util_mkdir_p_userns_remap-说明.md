# Taint Flow Analysis: `util_mkdir_p_userns_remap`

## Function Information
- **File**: src/utils/cutils/utils_file.c
- **Lines**: L194-L257
- **Signature**: `int util_mkdir_p_userns_remap(const char *dir, mode_t mode, const char *userns_remap)`

## Tainted Parameters

### [INPUT-1] `userns_remap` (const char *) 🔴 TAINTED
**Description**: External user-provided string for user namespace remapping configuration. Format expected: "uid:gid:size"

## Data Flow Trace

### INPUT-1: `userns_remap` (const char *) 🔴 TAINTED
├── [L210] `util_parse_user_remap(userns_remap, &host_uid, &host_gid, &size)` → **📎 Callee**
│   └── Result: Output parameters become new tainted carriers
│       ├── `host_uid` 🔴 TAINTED (derived from userns_remap parsing)
│       ├── `host_gid` 🔴 TAINTED (derived from userns_remap parsing)
│       └── `size` 🔴 TAINTED (derived from userns_remap parsing)
│
├── [L234] `chown(cur_dir, host_uid, host_gid)` → **⚠️ DIRECT_SINK**
│   └── **CRITICAL**: Tainted uid/gid values used directly in chown syscall
│       - `cur_dir` is derived from `dir` path (not from userns_remap directly)
│       - But ownership change is controlled by attacker-provided uid/gid
│
└── [L237] `return 0` (function exits)
    └── No tainted values returned directly, but chown side-effect already occurred

## Taint Propagation Details

### Step 1: Tainted Input Processing (Line 210)
```
if (util_parse_user_remap(userns_remap, &host_uid, &host_gid, &size)) {
    ERROR("Failed to split string '%s'.", userns_remap);
    goto err_out;
}
```
- **Observation**: `userns_remap` is passed to `util_parse_user_remap()` which parses the string by splitting on ':' and extracting three unsigned integers
- **Output Parameters**: The function writes parsed values to `host_uid`, `host_gid`, and `size`
- **Taint Propagation**: These output parameters become new tainted carriers because they derive their values from the externally-controlled `userns_remap` string

### Step 2: Tainted Values Used in System Call (Line 234)
```
if (ret == 0 && userns_remap != NULL && chown(cur_dir, host_uid, host_gid) != 0) {
    ERROR("Failed to chown host path '%s'.", cur_dir);
    goto err_out;
}
```
- **⚠️ DIRECT_SINK**: The tainted `host_uid` and `host_gid` values are used directly as arguments to the `chown()` system call
- **Security Impact**: An attacker who controls `userns_remap` can cause arbitrary ownership changes to directories created by this function
- **Severity**: High - allows privilege escalation by changing file ownership

## Callee List

| File | Function | Line | Tainted Arguments |
|------|----------|------|------------------|
| src/utils/cutils/utils.c | `util_parse_user_remap` | L1070 | `userns_remap` (1st arg) |

## Summary

| Tainted Parameter |终点| 位置 | 说明 |
|-------------------|---|------|------|
| `userns_remap` → `host_uid` | ⚠️ chown() | L234 | Tainted uid used in chown syscall |
| `userns_remap` → `host_gid` | ⚠️ chown() | L234 | Tainted gid used in chown syscall |
| `userns_remap` → `size` | 📌 NOT USED | - | Derived but unused in this function |

## Security Notes

1. **Taint Source**: `userns_remap` is an external configuration string that could come from container manifest or user input
2. **Taint Sink**: `chown()` syscall with attacker-controlled uid/gid
3. **Validation Gap**: The function uses `util_parse_user_remap` for parsing, which performs basic numeric validation, but the resulting uid/gid values are still attacker-controlled and can cause unauthorized ownership changes
4. **Scope**: The `size` parameter is extracted but not used within `util_mkdir_p_userns_remap` itself