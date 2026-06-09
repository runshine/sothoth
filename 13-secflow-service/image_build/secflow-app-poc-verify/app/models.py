"""Shared enums and utilities for poc-dynamic-verify."""

from enum import Enum


class VerifyStatus(str, Enum):
    REACHABLE = "reachable"
    UNREACHABLE = "unreachable"
    PARTIAL = "partial"
    ERROR = "error"


class PatchLevel(str, Enum):
    HARD_BLOCK = "HARD_BLOCK"
    ENV_MISSING = "ENV_MISSING"
    TIMING = "TIMING"
    NETWORK = "NETWORK"
    CRYPTO = "CRYPTO"
    UNKNOWN_SYSCALL = "UNKNOWN_SYSCALL"
