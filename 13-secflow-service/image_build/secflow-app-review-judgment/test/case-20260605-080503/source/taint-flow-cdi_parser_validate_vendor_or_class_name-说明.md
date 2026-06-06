# Taint Flow Report: `validate_vendor_or_class_name`

## Function Information
- **File:** `src/daemon/modules/device/cdi/behavior/parser/cdi_parser.c`
- **Lines:** L169-L195
- **Signature:** `static int validate_vendor_or_class_name(const char *name)`

---

## INPUT-1: `name` (const char *) 🔴 TAINTED

> External CDI configuration input — vendor/class name read from parsed CDI spec file. Treated as untrusted until validated.

### Propagation Trace

| Location | Code | Result | Annotation |
|----------|------|--------|------------|
| L171 | `if (name == NULL)` | — | Null guard; `name` read as pointer value (not dereferenced yet) |
| L174 | `if (!isalpha(name[0]))` | — | `name[0]` read → 🔴 TAINTED; passed to `isalpha()` → 🟡 EXPORT stdlib |
| L174 | `ERROR("%s, should start with letter", name)` | — | `name` passed to `ERROR()` as `%s` argument (logs tainted string) → 🟡 EXPORT logging |
| L175 | `return -1` | — | Returns error code, not tainted |
| L176 | `for (i = 1; name[i] != '\0'; i++)` | — | Loop condition reads `name[i]` → 🔴 TAINTED per iteration |
| L177 | `if (!(isalnum(name[i]) \|\| ...))` | — | `name[i]` read → 🔴 TAINTED; passed to `isalnum()` → 🟡 EXPORT stdlib |
| L177 | `ERROR("Invalid character '%c' in name %s", name[i], name)` | — | `name[i]` (char) and `name` both tainted → 🟡 EXPORT logging |
| L177 | `return -1` | — | Returns error code, not tainted |
| L180 | `if (!isalnum(name[i - 1]))` | — | `name[i-1]` read → 🔴 TAINTED; passed to `isalnum()` → 🟡 EXPORT stdlib |
| L180 | `ERROR("%s, should end with a letter or digit", name)` | — | `name` passed to `ERROR()` → 🟡 EXPORT logging |
| L180 | `return -1` | — | Returns error code, not tainted |
| L182 | `return 0` | — | Returns success code (not tainted) |

### Data Flow Tree

```
### INPUT-1: name (const char *) 🔴 TAINTED — external CDI config input
├── [L171] if (name == NULL) → null check, no propagation
├── [L174] isalpha(name[0]) → 🟡 EXPORT stdlib (isalpha)
├── [L174] ERROR(..., name) → 🟡 EXPORT logging
└── [L176] for (i=1; name[i]!='\0'; i++) → loop over tainted characters
    ├── [L177] isalnum(name[i]) → 🟡 EXPORT stdlib (isalnum)
    ├── [L177] name[i] == '_' | '-' | '.' → comparison with const
    ├── [L177] ERROR(..., name[i], name) → 🟡 EXPORT logging
    ├── [L180] isalnum(name[i-1]) → 🟡 EXPORT stdlib (isalnum)
    └── [L180] ERROR(..., name) → 🟡 EXPORT logging
        └── [L182/185/188] return 0/-1 → clean status code, 📌 USED (validation consumed)
```

---

## Taint Summary

| Input | Endpoint | Location | Type |
|-------|----------|----------|------|
| `name` | `isalpha()` — `name[0]` passed for character classification | L174 | 🟡 EXPORT stdlib |
| `name` | `isalnum()` — each `name[i]` passed in loop for char classification | L177 | 🟡 EXPORT stdlib |
| `name` | `isalnum()` — `name[i-1]` passed for end-char classification | L180 | 🟡 EXPORT stdlib |
| `name` | `ERROR()` logging calls — `name` used in error messages | L174, L177, L180 | 🟡 EXPORT logging |
| `name` | Return value — validation result consumed by caller | L182/L185/L188 | 📌 USED |

### New Tainted Carriers
**None.** No new objects are created in this function. No output parameters, buffers, or messages receive tainted data within this function body.

### Key Observations
1. `name` is **only consumed** (read-only) — it is never written into any output object.
2. Every tainted read of `name[i]` is immediately passed to `isalnum()`/`isalpha()` — standard library classification functions are sinks for data but do not propagate taint further.
3. All `ERROR()` calls are logging functions; `name` is formatted into log output (⚠️ information leak but not a memory safety issue).
4. **No DIRECT_SINK** operations in this function body — no `memcpy`/`strcpy` with tainted size, no tainted array index used for writing, no integer truncation.

---

## Sub-functions Called with Tainted Data

| Caller | Tainted Argument | Line | Callee Location | Notes |
|--------|-----------------|------|-----------------|-------|
| L196 | `vendor` → `validate_vendor_or_class_name(vendor)` | L197 | L169 (same file) | 🟡 EXPORT — caller in same file |
| L205 | `class` → `validate_vendor_or_class_name(class)` | L207 | L169 (same file) | 🟡 EXPORT — caller in same file |

> Both `cdi_parser_validate_vendor_name()` and `cdi_parser_validate_class_name()` are defined in the same file. Each wraps `validate_vendor_or_class_name()` by passing their respective tainted parameters (`vendor`/`class`) as the `name` argument. These two callers will be automatically queued for analysis.