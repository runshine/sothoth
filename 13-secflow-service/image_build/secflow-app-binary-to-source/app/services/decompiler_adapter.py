"""Third-party decompiler adapter (mock implementation)."""

import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class DecompileResult:
    status: str
    generated_files: List[str] = field(default_factory=list)
    message: str = ""
    error_reason: Optional[str] = None
    raw_payload: Dict[str, Any] = field(default_factory=dict)


class DecompilerAdapter:
    """
    Target third-party API signature:
    decompile_elf(input_elf_path: str, output_dir: str) -> DecompileResult
    """

    def decompile_elf(self, input_elf_path: str, output_dir: str) -> DecompileResult:
        os.makedirs(output_dir, exist_ok=True)

        basename = os.path.basename(input_elf_path).lower()
        if not os.path.exists(input_elf_path):
            return DecompileResult(
                status="failed",
                message="ELF file not found",
                error_reason="input_not_found",
                raw_payload={"input": input_elf_path},
            )

        if "fail" in basename:
            return DecompileResult(
                status="failed",
                message="Decompiler returned failed",
                error_reason="mock_worker_business_failure",
                raw_payload={"input": input_elf_path, "mode": "forced_failed"},
            )

        source_path = os.path.join(output_dir, "main.c")
        with open(source_path, "w", encoding="utf-8") as f:
            f.write("// mock decompiled source\nint main(){return 0;}\n")

        generated = [source_path]
        if "partial" in basename:
            warn_file = os.path.join(output_dir, "warning.txt")
            with open(warn_file, "w", encoding="utf-8") as f:
                f.write("partial success: some symbols missing\n")
            generated.append(warn_file)
            return DecompileResult(
                status="partial_success",
                generated_files=generated,
                message="Decompile partial success",
                error_reason="mock_partial_missing_symbols",
                raw_payload={"input": input_elf_path, "mode": "partial"},
            )

        return DecompileResult(
            status="success",
            generated_files=generated,
            message="Decompile success",
            raw_payload={"input": input_elf_path, "mode": "success"},
        )


_adapter: Optional[DecompilerAdapter] = None


def get_decompiler_adapter() -> DecompilerAdapter:
    global _adapter
    if _adapter is None:
        _adapter = DecompilerAdapter()
    return _adapter
