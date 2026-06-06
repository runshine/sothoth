# Data Flow Report: util_smart_calloc_s

**File**: `src/utils/cutils/utils_string.c`  
**Lines**: L309-L312 (snippet only; full function definition not found in workspace)  
**Status**: ⚠️ PARTIAL SOURCE — only the call site context is available

---

## Taint Sources (from Parent: cdi_parser_validate_vendor_name L157)

| # | Symbol | Kind | Description |
|---|--------|------|-------------|
| T1 | `add_capacity` | param | Tainted capacity increment from `cdi_parser_validate_vendor_name`; originates from attacker-controlled file content |

---

## Taint Propagation Path

```
cdi_parser_validate_vendor_name L157
 └── util_smart_calloc_s(sizeof(char *), new_size)
         └── new_size = add_capacity 🔴 TAINTED
             └── L309: util_smart_calloc_s(...) ⚠️ ALLOCATION_SINK
                 └── Taint terminates here (EXPORT: standard memory allocator)
```

**Key observation:**
- `sizeof(char *)` = constant (clean) — compile-time known value
- `new_size` = derived from `add_capacity` (tainted) — attacker controls allocation size
- The function name `util_smart_calloc_s` suggests it performs smart/capped allocation (likely `count * size` with overflow protection or limits)
- **Without the full function body**, we cannot verify if `util_smart_calloc_s` properly guards against overflow

---

## Critical Sink Summary

| Location | Operation | Tainted Data | Risk |
|----------|-----------|--------------|------|
| **L309** | `util_smart_calloc_s(sizeof(char *), new_size)` | `new_size` = `add_capacity` (attacker-controlled) | **Integer overflow**: taint controls allocation size; if internal `count * size` overflows, undersized buffer allocated → heap overflow |
| **L309** | `util_smart_calloc_s(sizeof(char *), new_size)` | `new_size` = `add_capacity` | **Memory exhaustion DoS**: attacker requests huge allocation |

---

## Sanitization / Validation (Cannot Verify)

**Partial source only** — the full function body of `util_smart_calloc_s` is not available in the workspace. Whether the function:
- Checks for integer overflow in `count * size` — **unknown**
- Caps `new_size` to a maximum value — **unknown**
- Returns NULL on excessive allocation — **possible** (L310 shows NULL check)

Standard "smart" allocators in container codebases often include overflow guards, but this cannot be confirmed without the source.

---

## Call Chain Context

```
rt_lcr_start (L175)
 └─ lcr_rt_read_pidfile (pidfile from attacker-controlled path)
     └─ parse_container_pid
         └─ command_get_string_dup_option_data
             └─ cdi_parser_validate_vendor_name (NOT FOUND)
                 └─ util_smart_calloc_s(L309) ⚠️ ALLOCATION_SINK
                     └── add_capacity 🔴 (tainted)
```

---

## Termination Status

**TERMINATED** (EXPORT rule) — `util_smart_calloc_s` is a standard memory allocation wrapper function. Per analysis rules, standard allocation functions are marked `🟡 EXPORT` and not recursively analyzed. Taint propagation terminates at this boundary.

---

## Vulnerability Candidates

1. **HIGH — Integer Overflow in Allocation Size**: `add_capacity` (attacker-controlled) flows to `new_size` → `util_smart_calloc_s` performs `sizeof(char*) * new_size`. If overflow occurs, allocation succeeds with undersized buffer → heap buffer overflow on subsequent writes.
2. **MEDIUM — Memory Exhaustion DoS**: `add_capacity` controls allocation size → attacker can trigger excessive memory allocation.