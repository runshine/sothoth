from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

from sqlalchemy.orm import Session

from app.exception import ValidationError
from app.model import BinarySecurityArchiveJob, BinarySecurityStageItem, BinarySecurityTask, TASK_TYPE_SOURCE, normalize_stage_name

if TYPE_CHECKING:
    from app.service.task_manager import TaskManager


class TaskContractServiceMixin:
    def _resolve_module_binary_paths(self: TaskManager, module: dict[str, Any] | None) -> list[str]:
        raw = dict(module or {})
        files_list = str(raw.get("files_list") or raw.get("files_list_path") or "").strip()
        unpacked_root = str(raw.get("unpacked_root") or raw.get("source_root") or "").strip()
        candidates: list[str] = []
        seen: set[str] = set()
        if files_list and unpacked_root:
            file_path = Path(files_list)
            root_path = Path(unpacked_root)
            if file_path.is_file():
                for line in file_path.read_text(encoding="utf-8").splitlines():
                    relative = line.strip().replace("\\", "/")
                    if not relative:
                        continue
                    resolved = (root_path / relative).resolve()
                    if resolved.is_file():
                        key = str(resolved)
                        if key not in seen:
                            seen.add(key)
                            candidates.append(key)
        module_dir = str(raw.get("module_dir") or raw.get("source_dir") or "").strip()
        if not candidates and module_dir:
            root = Path(module_dir)
            if root.is_dir():
                for current in sorted(root.rglob("*")):
                    if current.is_file():
                        key = str(current.resolve())
                        if key not in seen:
                            seen.add(key)
                            candidates.append(key)
        return candidates

    def _choose_module_binary(self: TaskManager, module: dict[str, Any] | None) -> str | None:
        paths = self._resolve_module_binary_paths(module)
        return paths[0] if paths else None

    def _build_module_elf_tasks(self: TaskManager, module: dict[str, Any] | None) -> list[dict[str, Any]]:
        payload = dict(module or {})
        elf_paths = self._resolve_module_binary_paths(payload)
        total = len(elf_paths)
        tasks: list[dict[str, Any]] = []
        for index, elf_path in enumerate(elf_paths, start=1):
            tasks.append(
                {
                    "elf_path": elf_path,
                    "file_list": [elf_path],
                    "metadata": {
                        "module_key": payload.get("module_key"),
                        "module_name": payload.get("module_name"),
                        "risk_level": payload.get("risk_level"),
                        "module_file_index": index,
                        "module_file_count": total,
                        "module_all_elf_paths": list(elf_paths),
                    },
                }
            )
        return tasks

    def _compact_result_for_storage(self: TaskManager, stage_name: str, item: dict[str, Any]) -> dict[str, Any]:
        from app.service import task_manager as task_manager_module

        if not isinstance(item, dict):
            return {}
        result = dict(item)
        if "downstream" in result:
            result["downstream"] = self._lightweight_downstream_payload(result.get("downstream") or {})
        if "artifacts" in result:
            result["artifacts"] = self._lightweight_artifacts_payload(result.get("artifacts") or {})
        if stage_name == "entry_analysis":
            entries = [dict(row) for row in result.get("entries") or [] if isinstance(row, dict)]
            result["entry_count"] = len(entries)
            result["entries_preview"] = self._compact_entry_rows(
                entries[: min(task_manager_module.DB_ENTRY_PREVIEW_LIMIT, 5)],
                summary_only=True,
            )
            result.pop("entries", None)
        elif normalize_stage_name(stage_name) == "dataflow_vuln_scan":
            artifact_files = result.get("artifact_files") or []
            if isinstance(artifact_files, list):
                result["artifact_file_count"] = len(artifact_files)
                result["artifact_files_preview"] = artifact_files[: task_manager_module.DB_ARTIFACT_PREVIEW_LIMIT]
            result.pop("artifact_files", None)
        return result

    def _lightweight_system_analysis_result(self: TaskManager, result_payload: dict[str, Any] | None) -> dict[str, Any]:
        payload = result_payload or {}
        raw_summary = payload.get("summary")
        if isinstance(raw_summary, dict):
            summary = {
                key: value
                for key, value in raw_summary.items()
                if isinstance(value, (int, float, bool)) or (isinstance(value, str) and len(value) <= 500)
            }
        elif isinstance(raw_summary, str):
            summary = {"message": raw_summary[:500]}
        else:
            summary = {}
        modules = self._lightweight_modules_for_storage(list(payload.get("modules") or []))
        return {
            "available": payload.get("available"),
            "status": payload.get("status"),
            "output_root": payload.get("output_root"),
            "final_report_path": payload.get("final_report_path"),
            "modules_list_path": payload.get("modules_list_path"),
            "summary": summary,
            "module_count": len(modules),
            "modules": modules,
            "warnings": payload.get("warnings") or [],
        }

    def _lightweight_system_analysis_items(self: TaskManager, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        rows = []
        for item in items:
            row = dict(item)
            row["modules"] = self._lightweight_modules_for_storage(list(row.get("modules") or []))
            if "system_analysis_result" in row:
                row["system_analysis_result"] = self._lightweight_system_analysis_result(
                    row.get("system_analysis_result") or {}
                )
            rows.append(row)
        return rows

    def _lightweight_modules_for_storage(
        self: TaskManager,
        modules: list[dict[str, Any]],
        *,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        rows = []
        for module in modules[:limit]:
            rows.append(
                {
                    "module_key": module.get("module_key"),
                    "module_name": module.get("module_name"),
                    "rank": module.get("rank"),
                    "risk_level": self._normalize_module_risk_level(module.get("risk_level")),
                    "risk_score": module.get("risk_score"),
                    "file_count": module.get("file_count"),
                }
            )
        return rows

    def _is_valid_system_analysis_input(self: TaskManager, row: dict[str, Any]) -> bool:
        return bool(str(row.get("firmware_key") or "").strip())

    def _normalize_system_analysis_input(self: TaskManager, row: dict[str, Any]) -> dict[str, Any]:
        from app.service import task_manager as task_manager_module

        firmware_key = str(row.get("firmware_key") or row.get("item_key") or row.get("filename") or "").strip()
        unpacked_root = str(row.get("unpacked_root") or row.get("source_root") or row.get("archive_root") or "").strip()
        filename = str(row.get("filename") or firmware_key or "firmware").strip()
        return {
            "firmware_key": firmware_key,
            "firmware_name": str(row.get("firmware_name") or Path(filename).stem or firmware_key).strip(),
            "filename": filename,
            "input_path": str(row.get("input_path") or row.get("path") or "").strip(),
            "unpacked_root": unpacked_root,
            "source_root": str(row.get("source_root") or unpacked_root).strip(),
            "task_type": row.get("task_type") or task_manager_module.TASK_TYPE_BINARY,
        }

    def _system_analysis_inputs_from_firmware_items(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
    ) -> list[dict[str, Any]]:
        from app.service import task_manager as task_manager_module

        rows: list[dict[str, Any]] = []
        archive_jobs_by_item = self._stage_archive_jobs_by_item(db, task.id, "firmware_unpack")
        for item in self._stage_items(db, task.id, "firmware_unpack"):
            if self._normalize_item_status(item.status) != "success":
                continue
            input_ref = dict(item.input_ref or {})
            result = self._load_stage_item_result_payload(item)
            archive_root = self._stage_item_archive_root(
                item,
                archive_jobs=archive_jobs_by_item.get(str(item.id or ""), []),
            )
            candidate = self._normalize_system_analysis_input(
                {
                    **input_ref,
                    **result,
                    "firmware_key": result.get("firmware_key") or item.item_key or input_ref.get("firmware_key"),
                    "firmware_name": result.get("firmware_name") or item.item_name or input_ref.get("firmware_name"),
                    "filename": result.get("filename") or input_ref.get("filename") or item.item_name or item.item_key,
                    "input_path": result.get("input_path") or input_ref.get("path") or input_ref.get("input_path"),
                    "unpacked_root": result.get("unpacked_root") or archive_root,
                    "source_root": result.get("source_root") or result.get("unpacked_root") or archive_root,
                    "task_type": result.get("task_type") or task_manager_module.TASK_TYPE_BINARY,
                }
            )
            if self._is_valid_system_analysis_input(candidate):
                rows.append(candidate)
        return rows

    def _system_analysis_inputs(
        self: TaskManager,
        task: BinarySecurityTask,
        db: Session | None = None,
    ) -> list[dict[str, Any]]:
        from app.service import task_manager as task_manager_module

        if self._task_type(task) == task_manager_module.TASK_TYPE_SOURCE:
            input_dir = Path(task.workspace_root) / "input"
            if not input_dir.exists():
                return []
            return [
                {
                    "firmware_key": task_manager_module.SOURCE_TASK_INPUT_KEY,
                    "firmware_name": task.name,
                    "filename": "source-project",
                    "unpacked_root": str(input_dir),
                    "source_root": str(input_dir),
                    "task_type": task_manager_module.TASK_TYPE_SOURCE,
                }
            ]
        summary_rows = [
            self._normalize_system_analysis_input(row)
            for row in list(task.summary.get("firmware_unpack_results") or [])
            if isinstance(row, dict)
        ]
        valid_summary_rows = [row for row in summary_rows if self._is_valid_system_analysis_input(row)]
        if valid_summary_rows:
            return valid_summary_rows
        if db is not None:
            return self._system_analysis_inputs_from_firmware_items(db, task)
        return []

    def _lightweight_system_analysis_input(self: TaskManager, firmware: dict[str, Any]) -> dict[str, Any]:
        from app.service import task_manager as task_manager_module

        return {
            "firmware_key": firmware.get("firmware_key"),
            "firmware_name": firmware.get("firmware_name"),
            "filename": firmware.get("filename"),
            "unpacked_root": firmware.get("unpacked_root"),
            "source_root": firmware.get("source_root") or firmware.get("unpacked_root"),
            "task_type": firmware.get("task_type", task_manager_module.TASK_TYPE_BINARY),
        }

    def _system_analysis_modules_for_task(self: TaskManager, db: Session, task: BinarySecurityTask) -> list[dict[str, Any]]:
        items = self._stage_items(db, task.id, "system_analysis")
        archive_jobs_by_item = self._stage_archive_jobs_by_item(db, task.id, "system_analysis")
        modules: list[dict[str, Any]] = []
        seen_module_keys: set[str] = set()
        for item in items:
            if item.status != "success":
                continue
            item_modules = self._system_analysis_modules_from_item(
                task,
                item,
                archive_jobs=archive_jobs_by_item.get(str(item.id or ""), []),
            )
            for module in item_modules:
                module_key = str(module.get("module_key") or "").strip()
                if not module_key or module_key in seen_module_keys:
                    continue
                seen_module_keys.add(module_key)
                modules.append(module)
        return modules

    def _system_analysis_modules_from_item(
        self: TaskManager,
        task: BinarySecurityTask,
        item: BinarySecurityStageItem,
        *,
        archive_jobs: list[BinarySecurityArchiveJob] | None = None,
    ) -> list[dict[str, Any]]:
        from app.service import task_manager as task_manager_module

        result = self._load_stage_item_result_payload(item)
        artifact_root = Path(self._stage_item_artifact_root(item, archive_jobs=archive_jobs))
        modules_file = artifact_root / "system_analysis_modules.json"
        base_firmware = self._normalize_system_analysis_input(
            {
                **dict(item.input_ref or {}),
                **result,
                "firmware_key": result.get("firmware_key") or item.item_key or (item.input_ref or {}).get("firmware_key"),
                "firmware_name": result.get("firmware_name") or item.item_name or (item.input_ref or {}).get("firmware_name"),
                "filename": result.get("filename") or (item.input_ref or {}).get("filename") or item.item_name or item.item_key,
                "input_path": result.get("input_path") or (item.input_ref or {}).get("input_path") or (item.input_ref or {}).get("path"),
                "unpacked_root": result.get("unpacked_root") or result.get("source_root") or str(artifact_root),
                "source_root": result.get("source_root") or result.get("unpacked_root") or str(artifact_root),
                "task_type": result.get("task_type") or self._task_type(task),
            }
        )

        def _enrich(row: dict[str, Any], index: int) -> dict[str, Any]:
            module_name = str(row.get("module_name") or row.get("name") or "").strip()
            module_key = str(row.get("module_key") or "").strip() or task_manager_module._slug(
                f"{base_firmware['firmware_key']}-{module_name or index + 1}"
            )
            source_root = str(
                row.get("source_root") or base_firmware.get("source_root") or base_firmware.get("unpacked_root") or ""
            ).strip()
            module_dir = str(row.get("module_dir") or row.get("module_dir_path") or "").strip()
            source_dir = str(row.get("source_dir") or module_dir or source_root).strip()
            files_list = str(row.get("files_list") or row.get("files_list_path") or "").strip()
            enriched = {
                **base_firmware,
                **dict(row),
                "module_key": module_key,
                "module_name": module_name or module_key,
                "module_dir": module_dir or source_dir,
                "source_dir": source_dir,
                "source_root": source_root,
                "source_root_path": str(row.get("source_root_path") or source_root).strip(),
                "files_list": files_list,
                "files_list_path": str(row.get("files_list_path") or files_list).strip(),
                "task_type": row.get("task_type") or base_firmware.get("task_type") or self._task_type(task),
            }
            return enriched

        if modules_file.is_file():
            try:
                payload = task_manager_module.json.loads(task_manager_module._read_text(modules_file) or "{}")
                rows = payload.get("items") or []
                if isinstance(rows, list):
                    return [_enrich(dict(row), index) for index, row in enumerate(rows) if isinstance(row, dict)]
            except Exception:
                pass
        modules = result.get("modules") or []
        return [_enrich(dict(row), index) for index, row in enumerate(modules) if isinstance(row, dict)]

    def _parse_system_analysis_modules(
        self: TaskManager,
        root: Path,
        firmware: dict[str, Any],
        result_payload: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        from app.service import task_manager as task_manager_module

        result_payload = result_payload or {}
        modules_list = root / "modules.list"
        modules_dir = root / "modules"
        items: list[dict[str, Any]] = []
        result_modules = list(result_payload.get("modules") or [])
        if result_modules:
            for module in sorted(result_modules, key=lambda item: int(item.get("rank") or 0)):
                name = str(module.get("module_name") or "").strip()
                if not name:
                    continue
                archived_module_dir = modules_dir / name
                reported_module_dir = Path(str(module.get("module_dir_path") or archived_module_dir))
                module_dir = archived_module_dir if archived_module_dir.is_dir() else reported_module_dir
                archived_files_list = module_dir / "files.list"
                reported_files_list = Path(str(module.get("files_list_path") or archived_files_list))
                files_list = archived_files_list if archived_files_list.is_file() else reported_files_list
                archived_module_report = module_dir / "module_report.md"
                reported_module_report = Path(str(module.get("module_report_path") or archived_module_report))
                module_report = archived_module_report if archived_module_report.is_file() else reported_module_report
                source_dir = module_dir if module_dir.is_dir() else Path(
                    str(firmware.get("source_root") or firmware.get("unpacked_root") or root)
                )
                module_key = task_manager_module._slug(f"{firmware['firmware_key']}-{name}")
                items.append(
                    {
                        "firmware_key": firmware["firmware_key"],
                        "firmware_name": firmware["firmware_name"],
                        "filename": firmware["filename"],
                        "unpacked_root": firmware["unpacked_root"],
                        "source_root": firmware.get("source_root") or firmware.get("unpacked_root"),
                        "task_type": firmware.get("task_type", task_manager_module.TASK_TYPE_BINARY),
                        "module_key": module_key,
                        "module_name": name,
                        "module_dir": str(module_dir),
                        "source_dir": str(source_dir),
                        "module_report": str(module_report),
                        "files_list": str(files_list),
                        "risk_level": task_manager_module._normalize_module_risk_level(module.get("risk_level")),
                        "risk_score": int(module.get("risk_score") or 0),
                        "rank": int(module.get("rank") or 0),
                        "selected_by": None,
                        "selected_at": None,
                    }
                )
            task_manager_module._write_json(root / "system_analysis_modules.json", {"items": items})
            task_manager_module._write_json(root / "high_risk_modules.json", {"items": items})
            return items
        names = [line.strip() for line in task_manager_module._read_text(modules_list).splitlines() if line.strip()]
        if not names and modules_dir.is_dir():
            names = [path.name for path in sorted(p for p in modules_dir.iterdir() if p.is_dir())]
        if not names and self._task_type(firmware.get("task_type")) == task_manager_module.TASK_TYPE_SOURCE:
            names = ["source-project"]
        for name in names:
            module_dir = modules_dir / name
            source_dir = module_dir if module_dir.is_dir() else Path(
                str(firmware.get("source_root") or firmware.get("unpacked_root") or root)
            )
            module_key = task_manager_module._slug(f"{firmware['firmware_key']}-{name}")
            items.append(
                {
                    "firmware_key": firmware["firmware_key"],
                    "firmware_name": firmware["firmware_name"],
                    "filename": firmware["filename"],
                    "unpacked_root": firmware["unpacked_root"],
                    "source_root": firmware.get("source_root") or firmware.get("unpacked_root"),
                    "task_type": firmware.get("task_type", task_manager_module.TASK_TYPE_BINARY),
                    "module_key": module_key,
                    "module_name": name,
                    "module_dir": str(module_dir),
                    "source_dir": str(source_dir),
                    "module_report": str(module_dir / "module_report.md"),
                    "files_list": str(module_dir / "files.list"),
                    "risk_level": task_manager_module._normalize_module_risk_level(""),
                    "risk_score": 0,
                    "rank": len(items) + 1,
                    "selected_by": None,
                    "selected_at": None,
                }
            )
        task_manager_module._write_json(root / "system_analysis_modules.json", {"items": items})
        task_manager_module._write_json(root / "high_risk_modules.json", {"items": items})
        return items

    def _entry_analysis_inputs(self: TaskManager, db: Session, task: BinarySecurityTask) -> list[dict[str, Any]]:
        from app.service import task_manager as task_manager_module

        if self._task_type(task) == task_manager_module.TASK_TYPE_SOURCE:
            selected_modules = [dict(module) for module in (task.summary.get("selected_modules") or []) if isinstance(module, dict)]
            if selected_modules and any(
                not str(module.get("firmware_key") or "").strip()
                or not str(module.get("source_root") or module.get("source_root_path") or "").strip()
                or not str(module.get("source_dir") or module.get("module_dir") or "").strip()
                for module in selected_modules
            ):
                self._refresh_system_analysis_stage_from_synced_items(db, task)
                selected_modules = [dict(module) for module in (task.summary.get("selected_modules") or []) if isinstance(module, dict)]
            return selected_modules
        b2s_results = list(task.summary.get("b2s_results") or [])
        if b2s_results:
            normalized = [self._normalize_entry_analysis_module_input(task, module) for module in b2s_results if isinstance(module, dict)]
            if normalized != b2s_results:
                task.summary = {**(task.summary or {}), "b2s_results": normalized}
            if self._task_type(task) == task_manager_module.TASK_TYPE_BINARY_MODULE:
                ready = [module for module in normalized if module.get("entry_descriptor_ready")]
                if ready:
                    return ready
            return normalized
        rebuilt = self._rebuild_summary_results_from_stage_items(db, task, "binary_to_source", "b2s_results")
        normalized = [self._normalize_entry_analysis_module_input(task, module) for module in (rebuilt or []) if isinstance(module, dict)]
        if normalized and normalized != rebuilt:
            task.summary = {**(task.summary or {}), "b2s_results": normalized}
        if self._task_type(task) == task_manager_module.TASK_TYPE_BINARY_MODULE:
            ready = [module for module in normalized if module.get("entry_descriptor_ready")]
            if ready:
                return ready
        return list(normalized or [])

    def _missing_entry_analysis_input_reason(self: TaskManager, db: Session, task: BinarySecurityTask) -> str:
        from app.service import task_manager as task_manager_module

        items = self._stage_items(db, task.id, "binary_to_source")
        if not items:
            return "binary-to-source 阶段尚未产出任何可用于入口分析的源码模块"
        active_statuses = {"pending", "queued", "running", "dispatching"}
        active_items = [item for item in items if (self._normalize_downstream_status(item.status) or item.status) in active_statuses]
        if active_items:
            return "binary-to-source 阶段仍在运行，尚未生成可用于入口分析的源码产物"
        success_items = [item for item in items if (self._normalize_downstream_status(item.status) or item.status) == "success"]
        if success_items:
            if self._task_type(task) == task_manager_module.TASK_TYPE_BINARY_MODULE:
                return "binary-to-source 已成功，但未生成入口分析所需模块描述文件"
            return "binary-to-source 阶段已有成功条目，但未找到可用于入口分析的源码产物"
        failed_items = [
            item
            for item in items
            if (self._normalize_downstream_status(item.status) or item.status) in {"failed", "cancelled", "downstream_missing"}
        ]
        first_error = next((str(item.error_message).strip() for item in failed_items if str(item.error_message).strip()), "")
        if first_error:
            return first_error
        if failed_items:
            return "binary-to-source 阶段没有成功产物，无法推进入口分析"
        return "没有可用于入口分析的源码模块"

    def _build_entry_analysis_input_contract(self: TaskManager, entry_input: dict[str, Any]) -> dict[str, Any]:
        files_list_path = str(
            entry_input.get("files_list_path")
            or entry_input.get("entry_files_list")
            or entry_input.get("files_list")
            or ""
        ).strip()
        if not files_list_path:
            source_dir = str(entry_input.get("source_dir") or "").strip()
            module_dir = str(entry_input.get("module_dir") or source_dir).strip()
            if source_dir and module_dir:
                files_list_path = source_dir
        contract = {
            "module_dir": str(entry_input.get("module_dir") or entry_input.get("source_dir") or "").strip(),
            "files_list_path": files_list_path,
            "source_root": str(
                entry_input.get("source_root")
                or entry_input.get("source_root_path")
                or entry_input.get("entry_descriptor_root")
                or entry_input.get("source_dir")
                or ""
            ).strip(),
            "source_root_path": str(
                entry_input.get("source_root_path")
                or entry_input.get("source_root")
                or entry_input.get("entry_descriptor_root")
                or entry_input.get("source_dir")
                or ""
            ).strip(),
            "source_dir": str(entry_input.get("source_dir") or "").strip(),
            "files_list": str(entry_input.get("files_list") or "").strip(),
            "entry_descriptor_root": str(entry_input.get("entry_descriptor_root") or "").strip(),
            "entry_files_list": str(entry_input.get("entry_files_list") or "").strip(),
        }
        required_fields = ("module_dir", "source_root")
        missing = [field for field in required_fields if not contract.get(field)]
        if missing:
            raise ValidationError("binary_security 下发给 entry_analysis 的 input_contract 缺少: " + ", ".join(missing))
        return contract

    def _resolve_entry_source_dir(self: TaskManager, entry: dict[str, Any]) -> str:
        if not isinstance(entry, dict):
            return ""

        task_type = self._task_type(entry.get("task_type"))
        nested_entries = entry.get("entries") or entry.get("entries_preview") or []
        if isinstance(nested_entries, list):
            for nested in nested_entries:
                if isinstance(nested, dict):
                    nested_value = self._resolve_entry_source_dir(
                        {k: v for k, v in nested.items() if k not in {"entries", "entries_preview"}}
                    )
                    if nested_value:
                        return nested_value

        if task_type == TASK_TYPE_SOURCE:
            preferred = [
                entry.get("source_root"),
                entry.get("unpacked_root"),
                entry.get("source_dir"),
                entry.get("entry_descriptor_root"),
                entry.get("module_dir"),
                entry.get("artifact_root"),
                entry.get("archive_root"),
            ]
        else:
            preferred = [
                entry.get("source_dir"),
                entry.get("source_root"),
                entry.get("entry_descriptor_root"),
                entry.get("module_dir"),
                entry.get("artifact_root"),
                entry.get("archive_root"),
                entry.get("unpacked_root"),
            ]
        for candidate in preferred:
            value = str(candidate or "").strip()
            if value:
                return value

        definition_file = str(entry.get("definition_file") or entry.get("file_name") or "").strip()
        if definition_file:
            definition_path = Path(definition_file)
            return str(definition_path.parent if definition_path.suffix else definition_path)
        return ""

    def _resolve_dfa_module_input_path(self: TaskManager, entry: dict[str, Any]) -> str:
        if not isinstance(entry, dict):
            return ""
        for candidate in (
            entry.get("module_input_path"),
            entry.get("module_dir"),
            entry.get("entry_descriptor_root"),
            entry.get("source_dir"),
            entry.get("artifact_root"),
            entry.get("archive_root"),
        ):
            value = str(candidate or "").strip()
            if value:
                return value
        return ""

    def _is_supported_entry_source_file(self: TaskManager, path: Path) -> bool:
        lowered_parts = [part.lower() for part in path.parts]
        if "run" in lowered_parts:
            return False
        if "agent_sessions" in lowered_parts:
            return False
        lowered_name = path.name.lower()
        if "_ida." in lowered_name or lowered_name.endswith("_ida.c") or lowered_name.endswith("_ida.h"):
            return False
        if lowered_name.endswith(".chat.json") or lowered_name.endswith(".validate.json"):
            return False
        if lowered_name in {"functions.json", "imports.json", "metadata.json", "strings.json", "structural.json"}:
            return False
        return path.suffix.lower() in {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hh"}

    def _collect_entry_source_files(self: TaskManager, artifact_root: Path) -> list[Path]:
        if not artifact_root.is_dir():
            return []
        return [
            path
            for path in sorted(artifact_root.rglob("*"))
            if path.is_file() and self._is_supported_entry_source_file(path)
        ]

    def _normalize_entry_module_name(self: TaskManager, raw_name: str) -> str:
        cleaned = re.sub(r"[^0-9A-Za-z_.-]+", "_", str(raw_name or "").strip())
        cleaned = cleaned.strip("._-")
        return cleaned or "module"

    def _infer_entry_module_name(
        self: TaskManager,
        module: dict[str, Any],
        artifact_root: Path,
        source_files: list[Path],
    ) -> str:
        del artifact_root, source_files
        return self._normalize_entry_module_name(
            str(module.get("module_name") or module.get("entry_module_name") or "module")
        )

    def _prepare_entry_module_descriptor(self: TaskManager, artifact_root: Path, module: dict[str, Any]) -> dict[str, Any]:
        from app.service import task_manager as task_manager_module

        source_files = self._collect_entry_source_files(artifact_root)
        entry_module_name = self._infer_entry_module_name(module, artifact_root, source_files)
        descriptor_root = artifact_root
        module_dir = task_manager_module.ensure_dir(descriptor_root / "modules" / entry_module_name)
        files_list_path = module_dir / "files.list"
        relative_paths = [
            str(path.resolve().relative_to(artifact_root.resolve())).replace("\\", "/")
            for path in source_files
        ]
        files_list_path.write_text("\n".join(relative_paths) + ("\n" if relative_paths else ""), encoding="utf-8")
        return {
            "entry_module_name": entry_module_name,
            "entry_descriptor_root": str(descriptor_root),
            "entry_files_list": str(files_list_path),
            "entry_source_file_count": len(relative_paths),
            "entry_source_files_preview": relative_paths[:20],
            "entry_descriptor_ready": bool(relative_paths),
            "module_dir": str(module_dir),
            "files_list": str(files_list_path),
            "source_root": str(descriptor_root),
        }

    def _is_entry_descriptor_usable(self: TaskManager, descriptor_root: Path, files_list_path: Path) -> bool:
        try:
            resolved_root = descriptor_root.resolve()
            resolved_files_list = files_list_path.resolve()
            resolved_files_list.relative_to(resolved_root)
        except Exception:
            return False
        if not resolved_root.is_dir() or not resolved_files_list.is_file():
            return False
        try:
            rows = [line.strip() for line in resolved_files_list.read_text(encoding="utf-8").splitlines() if line.strip()]
        except Exception:
            return False
        if not rows:
            return False
        for relative_path in rows:
            candidate = resolved_root / relative_path
            if not candidate.is_file():
                return False
        return True

    def _entry_descriptor_candidates(self: TaskManager, module: dict[str, Any]) -> list[Path]:
        from app.service import task_manager as task_manager_module

        candidates: list[Path] = []
        for value in (
            module.get("entry_descriptor_root"),
            module.get("archive_root"),
            module.get("artifact_root"),
            module.get("source_dir"),
            module.get("source_root"),
            module.get("module_dir"),
        ):
            raw = str(value or "").strip()
            if not raw:
                continue
            candidates.append(Path(raw))
        return task_manager_module._dedupe_paths(candidates)

    def _normalize_entry_analysis_module_input(self: TaskManager, task: BinarySecurityTask, module: dict[str, Any]) -> dict[str, Any]:
        from app.service import task_manager as task_manager_module

        normalized = dict(module)
        if self._task_type(task) not in {task_manager_module.TASK_TYPE_BINARY_MODULE, task_manager_module.TASK_TYPE_BINARY}:
            return normalized
        entry_descriptor_root = str(normalized.get("entry_descriptor_root") or "").strip()
        entry_files_list = str(normalized.get("entry_files_list") or "").strip()
        if entry_descriptor_root and entry_files_list:
            descriptor_root_path = Path(entry_descriptor_root)
            files_list_path = Path(entry_files_list)
            if normalized.get("entry_descriptor_ready") and self._is_entry_descriptor_usable(descriptor_root_path, files_list_path):
                normalized["module_name"] = str(normalized.get("entry_module_name") or normalized.get("module_name") or "")
                normalized["source_dir"] = str(descriptor_root_path)
                normalized["source_root"] = str(descriptor_root_path)
                normalized["source_root_path"] = str(descriptor_root_path)
                normalized["module_dir"] = str(Path(entry_files_list).parent)
                normalized["files_list"] = str(files_list_path)
                normalized["files_list_path"] = str(files_list_path)
                return normalized
        for artifact_root in self._entry_descriptor_candidates(normalized):
            if not artifact_root.exists():
                continue
            prepared = self._prepare_entry_module_descriptor(artifact_root, normalized)
            if not prepared.get("entry_descriptor_ready"):
                continue
            prepared_descriptor_root = Path(str(prepared.get("entry_descriptor_root") or ""))
            files_list_path = Path(str(prepared.get("entry_files_list") or ""))
            if not self._is_entry_descriptor_usable(prepared_descriptor_root, files_list_path):
                continue
            normalized.update(prepared)
            normalized["module_name"] = str(prepared.get("entry_module_name") or normalized.get("module_name") or "")
            normalized["source_dir"] = str(prepared.get("entry_descriptor_root") or normalized.get("source_dir") or "")
            normalized["source_root"] = str(
                prepared.get("entry_descriptor_root")
                or prepared.get("source_root")
                or normalized.get("source_root")
                or ""
            )
            normalized["source_root_path"] = str(
                prepared.get("source_root_path")
                or prepared.get("entry_descriptor_root")
                or prepared.get("source_root")
                or normalized.get("source_root_path")
                or normalized.get("source_root")
                or ""
            )
            normalized["module_dir"] = str(prepared.get("module_dir") or normalized.get("module_dir") or "")
            normalized["files_list"] = str(prepared.get("files_list") or normalized.get("files_list") or "")
            normalized["files_list_path"] = str(
                prepared.get("files_list_path")
                or prepared.get("entry_files_list")
                or prepared.get("files_list")
                or normalized.get("files_list_path")
                or normalized.get("files_list")
                or ""
            )
            break
        return normalized

    def _build_entry_output_contract(
        self: TaskManager,
        module: dict[str, Any],
        entry: dict[str, Any],
        *,
        source_dir: str,
        module_input_path: str,
        source_root_path: str,
    ) -> dict[str, Any]:
        from app.service import task_manager as task_manager_module

        taint_params = [str(value).strip() for value in (entry.get("taint_params") or []) if str(value).strip()]
        signature_params = task_manager_module._entry_signature_params(entry)
        effective_taint_params = taint_params or signature_params
        return {
            "entry_key": entry.get("entry_key"),
            "firmware_key": module.get("firmware_key") or "",
            "firmware_name": module.get("firmware_name") or "",
            "module_key": module.get("module_key") or "",
            "module_name": module.get("module_name") or "",
            "file_name": entry.get("file_name"),
            "function_name": entry.get("function_name"),
            "raw_function_name": entry.get("raw_function_name"),
            "line_no": entry.get("line_no"),
            "definition_file": entry.get("definition_file") or entry.get("file_name"),
            "definition_line": entry.get("definition_line") or entry.get("line_no"),
            "is_definition_found": entry.get("is_definition_found", True),
            "definition_kind": self._resolve_entry_definition_kind(entry),
            "tag": entry.get("tag") or "P",
            "taint_params": effective_taint_params,
            "function_description": entry.get("function_description") or task_manager_module._default_entry_function_description(str(entry.get("function_name") or "")),
            "function_description_source": entry.get("function_description_source") or task_manager_module._entry_description_source(entry.get("function_description")),
            "entry_reason": entry.get("entry_reason") or task_manager_module._default_entry_reason(entry.get("tag"), str(entry.get("function_name") or "")),
            "entry_reason_source": entry.get("entry_reason_source") or task_manager_module._entry_description_source(entry.get("entry_reason")),
            "taint_details": task_manager_module._normalize_entry_taint_details(entry, effective_taint_params),
            "signature_params": signature_params,
            "entry_file": entry.get("entry_file"),
            "module_input_path": module_input_path,
            "source_root_path": source_root_path,
            "source_dir": source_dir,
        }

    def _validate_entry_output_contract(self: TaskManager, entry: dict[str, Any], *, allow_fallback: bool = False) -> dict[str, Any]:
        from app.service import task_manager as task_manager_module

        if not isinstance(entry, dict):
            raise ValidationError("入口分析输出 contract 非法")
        normalized = dict(entry)
        if allow_fallback:
            normalized["module_input_path"] = normalized.get("module_input_path") or self._resolve_dfa_module_input_path(normalized)
            normalized["source_root_path"] = normalized.get("source_root_path") or self._resolve_dfa_source_root_path(normalized)
            normalized["source_dir"] = normalized.get("source_dir") or self._resolve_entry_source_dir(normalized)
        for field, message in (
            ("entry_key", "入口分析输出缺少 entry_key"),
            ("module_key", "入口分析输出缺少 module_key"),
            ("module_name", "入口分析输出缺少 module_name"),
            ("function_name", "入口分析输出缺少 function_name"),
            ("definition_file", "入口分析输出缺少 definition_file"),
            ("definition_line", "入口分析输出缺少 definition_line"),
            ("definition_kind", "入口分析输出缺少 definition_kind"),
            ("module_input_path", "入口分析输出缺少 module_input_path"),
            ("source_root_path", "入口分析输出缺少 source_root_path"),
            ("source_dir", "入口分析输出缺少 source_dir"),
        ):
            if not str(normalized.get(field) or "").strip():
                raise ValidationError(message)
        if not isinstance(normalized.get("taint_params"), list):
            normalized["taint_params"] = []
        return normalized

    def _compress_source_file_hint(self: TaskManager, value: str) -> str:
        normalized = str(value or "").strip().replace("\\", "/")
        if not normalized:
            return ""
        if len(normalized) <= 240:
            return normalized
        digest = hashlib.sha1(normalized.encode("utf-8")).hexdigest()[:12]
        suffix = Path(normalized).name or "source"
        return f".../{suffix}#{digest}"

    def _validate_dataflow_output_contract(
        self: TaskManager,
        item: dict[str, Any],
        *,
        allow_fallback: bool = False,
    ) -> dict[str, Any]:
        if not isinstance(item, dict):
            raise ValidationError("数据流分析输出 contract 非法")
        normalized = dict(item)
        if allow_fallback:
            normalized["source_dir"] = normalized.get("source_dir") or self._resolve_entry_source_dir(normalized)
            normalized["module_input_path"] = normalized.get("module_input_path") or self._resolve_dfa_module_input_path(normalized)
            normalized["source_root_path"] = normalized.get("source_root_path") or self._resolve_dfa_source_root_path(normalized)
            normalized["dataflow_dir"] = normalized.get("dataflow_dir")
            normalized["data_flow_root"] = normalized.get("data_flow_root") or normalized.get("dataflow_dir")
        normalized["source_file"] = self._compress_source_file_hint(
            str(normalized.get("source_file") or normalized.get("definition_file") or normalized.get("file_name") or "")
        )
        for field, message in (
            ("entry_key", "数据流分析输出缺少 entry_key"),
            ("module_key", "数据流分析输出缺少 module_key"),
            ("module_name", "数据流分析输出缺少 module_name"),
            ("function_name", "数据流分析输出缺少 function_name"),
            ("source_dir", "数据流分析输出缺少 source_dir"),
            ("module_input_path", "数据流分析输出缺少 module_input_path"),
            ("source_root_path", "数据流分析输出缺少 source_root_path"),
            ("source_file", "数据流分析输出缺少 source_file"),
            ("dataflow_dir", "数据流分析输出缺少 dataflow_dir"),
        ):
            if not str(normalized.get(field) or "").strip():
                raise ValidationError(message)
        return normalized

    def _resolve_vuln_scan_dataflow_input_dir(self: TaskManager, item: dict[str, Any]) -> str:
        if not isinstance(item, dict):
            return ""
        for key in ("data_flow_root", "archive_root", "artifact_root"):
            candidate = str(item.get(key) or "").strip()
            if candidate:
                return candidate
        nested_dir = str(item.get("dataflow_dir") or "").strip()
        if nested_dir:
            nested_path = Path(nested_dir)
            if nested_path.name == "dataflow" and nested_path.parent != nested_path:
                return str(nested_path.parent)
            return nested_dir
        data_flow_file = str(item.get("data_flow_file") or item.get("primary_report_path") or "").strip()
        if data_flow_file:
            report_path = Path(data_flow_file)
            if report_path.name == "final_report.md" and report_path.parent != report_path:
                return str(report_path.parent)
        return ""

    def _resolve_dfa_source_root_path(self: TaskManager, entry: dict[str, Any]) -> str:
        if not isinstance(entry, dict):
            return ""
        preferred = [
            entry.get("source_root_path"),
            entry.get("source_root"),
            entry.get("source_dir"),
            entry.get("entry_descriptor_root"),
            entry.get("module_dir"),
            entry.get("artifact_root"),
            entry.get("archive_root"),
            entry.get("unpacked_root"),
        ]
        for candidate in preferred:
            value = str(candidate or "").strip()
            if value:
                return value

        definition_file = str(entry.get("definition_file") or entry.get("file_name") or "").strip()
        if definition_file:
            definition_path = Path(definition_file)
            return str(definition_path.parent if definition_path.suffix else definition_path)
        return ""

    def _normalize_dfa_source_file(self: TaskManager, source_root_path: str, entry: dict[str, Any]) -> str:
        normalized_root = str(source_root_path or "").strip()
        file_name = str(
            entry.get("source_file")
            or entry.get("definition_file")
            or entry.get("file_name")
            or ""
        ).strip()
        if not file_name:
            return ""
        normalized_file = file_name.replace("\\", "/")
        if not normalized_root:
            return self._compress_source_file_hint(normalized_file)
        try:
            file_path = Path(normalized_file)
            root_path = Path(normalized_root)
            if file_path.is_absolute():
                relative = file_path.resolve().relative_to(root_path.resolve())
                return self._compress_source_file_hint(str(relative).replace("\\", "/"))
        except Exception:
            pass
        return self._compress_source_file_hint(normalized_file)

    def _resolve_entry_definition_kind(self: TaskManager, entry: dict[str, Any]) -> str:
        kind = str(entry.get("definition_kind") or "").strip()
        if kind:
            return kind
        if entry.get("is_definition_found", True):
            return "definition"
        return "declaration"

    def _parse_entries(self: TaskManager, artifact_root: Path, module: dict[str, Any]) -> list[dict[str, Any]]:
        from app.service import task_manager as task_manager_module

        resolved_source_dir = self._resolve_entry_source_dir(module)
        resolved_module_input_path = self._resolve_dfa_module_input_path(module)
        resolved_source_root_path = self._resolve_dfa_source_root_path(module) or resolved_source_dir

        def _rows_from_payload(payload: Any, source: Path) -> list[dict[str, Any]]:
            if isinstance(payload, dict):
                raw_entries = payload.get("entries") or payload.get("items") or []
            elif isinstance(payload, list):
                raw_entries = payload
            else:
                raw_entries = []
            rows = []
            for index, entry in enumerate(raw_entries):
                if not isinstance(entry, dict):
                    continue
                raw_function_name = entry.get("function_name") or entry.get("function") or entry.get("name") or ""
                function_name = task_manager_module._normalize_entry_function_name(raw_function_name)
                if not function_name:
                    continue
                file_name = str(entry.get("file_name") or entry.get("file") or "").strip()
                line_no = str(entry.get("line_no") or entry.get("line") or index + 1)
                taint_params = [
                    str(value).strip()
                    for value in (entry.get("taints") or entry.get("taint_params") or [])
                    if str(value).strip()
                ]
                tag = str(entry.get("tag") or "").strip().upper()
                raw_function_description = str(entry.get("function_description") or "").strip()
                raw_entry_reason = str(entry.get("entry_reason") or "").strip()
                rows.append(
                    self._build_entry_output_contract(
                        module,
                        {
                            **entry,
                            "entry_key": task_manager_module._slug(
                                f"{module['module_key']}-{function_name}-{line_no}"
                            ),
                            "file_name": file_name,
                            "function_name": function_name,
                            "raw_function_name": str(raw_function_name or ""),
                            "line_no": line_no,
                            "definition_file": str(
                                entry.get("definition_file")
                                or entry.get("file_name")
                                or entry.get("file")
                                or file_name
                                or ""
                            ).strip(),
                            "definition_line": str(
                                entry.get("definition_line") or entry.get("line_no") or entry.get("line") or line_no
                            ),
                            "is_definition_found": bool(entry.get("is_definition_found", True)),
                            "tag": tag or "P",
                            "taint_params": taint_params,
                            "function_description": raw_function_description,
                            "entry_reason": raw_entry_reason,
                            "entry_file": str(source),
                        },
                        source_dir=resolved_source_dir,
                        module_input_path=resolved_module_input_path,
                        source_root_path=resolved_source_root_path,
                    )
                )
            return task_manager_module._deduplicate_entry_keys(rows)

        function_list_candidates = [
            artifact_root / "entry-details.json",
            artifact_root / "functions.list",
            artifact_root / "output" / "entry-details.json",
            artifact_root / "output" / "functions.list",
        ]
        if artifact_root.is_dir() and not any(candidate.is_file() for candidate in function_list_candidates):
            recursive_matches = sorted(artifact_root.rglob("functions.list"))
            if len(recursive_matches) == 1:
                function_list_candidates.append(recursive_matches[0])
        for candidate in function_list_candidates:
            if candidate.is_file():
                try:
                    rows = _rows_from_payload(json.loads(task_manager_module._read_text(candidate) or "[]"), candidate)
                    if rows:
                        return rows
                except Exception:
                    pass

        json_candidates = [
            artifact_root / "result.json",
            artifact_root / "result_json",
            artifact_root / "entry-list.json",
        ]
        for candidate in json_candidates:
            if candidate.is_file():
                payload = json.loads(task_manager_module._read_text(candidate) or "{}")
                rows = _rows_from_payload(payload, candidate)
                if rows:
                    return rows
        entry_file = artifact_root / "entry-list.md"
        content = task_manager_module._read_text(entry_file)
        rows = []
        for line in content.splitlines():
            parts = [part.strip() for part in line.split("|")]
            if parts and not parts[0]:
                parts = parts[1:]
            if parts and not parts[-1]:
                parts = parts[:-1]
            if len(parts) >= 7 and parts[1].isdigit():
                file_name = parts[2]
                function_name = task_manager_module._normalize_entry_function_name(parts[3])
                line_no = parts[4]
                if file_name and function_name:
                    taint_params = [part.strip() for part in parts[5].split(",") if part.strip()] if len(parts) > 5 else []
                    rows.append(
                        self._build_entry_output_contract(
                            module,
                            {
                                "entry_key": task_manager_module._slug(
                                    f"{module['module_key']}-{function_name}-{line_no}"
                                ),
                                "file_name": file_name,
                                "function_name": function_name,
                                "raw_function_name": parts[3],
                                "line_no": line_no,
                                "tag": "P",
                                "definition_kind": "definition",
                                "taint_params": taint_params,
                                "function_description": task_manager_module._default_entry_function_description(function_name),
                                "function_description_source": "default",
                                "entry_reason": task_manager_module._default_entry_reason("P", function_name),
                                "entry_reason_source": "default",
                                "taint_details": task_manager_module._normalize_entry_taint_details({"taint_details": []}, taint_params),
                                "entry_file": str(entry_file),
                            },
                            source_dir=resolved_source_dir,
                            module_input_path=resolved_module_input_path,
                            source_root_path=resolved_source_root_path,
                        )
                    )
        return task_manager_module._deduplicate_entry_keys(rows)

    def _build_dataflow_output_contract(
        self: TaskManager,
        entry: dict[str, Any],
        *,
        artifact_root: str,
        archive_root: str,
        module_input_path: str,
        source_root_path: str,
        source_file: str,
        data_flow_file: str,
        dataflow_dir: str,
        source_dir: str,
    ) -> dict[str, Any]:
        return {
            **entry,
            "artifact_root": artifact_root,
            "archive_root": archive_root,
            "module_input_path": module_input_path,
            "source_root_path": source_root_path,
            "source_dir": source_dir,
            "source_file": source_file,
            "data_flow_root": artifact_root,
            "dataflow_dir": dataflow_dir,
        }

    def _compact_entry_rows(self: TaskManager, entries: list[dict[str, Any]], *, summary_only: bool = False) -> list[dict[str, Any]]:
        from app.service import task_manager as task_manager_module

        rows: list[dict[str, Any]] = []
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            signature_params = task_manager_module._entry_signature_params(entry)
            taint_params = [str(value).strip() for value in (entry.get("taint_params") or []) if str(value).strip()] or signature_params
            row = {
                "entry_key": entry.get("entry_key"),
                "firmware_key": entry.get("firmware_key"),
                "firmware_name": entry.get("firmware_name"),
                "module_key": entry.get("module_key"),
                "module_name": entry.get("module_name"),
                "file_name": entry.get("file_name"),
                "function_name": entry.get("function_name"),
                "raw_function_name": entry.get("raw_function_name"),
                "line_no": entry.get("line_no"),
                "definition_file": entry.get("definition_file") or entry.get("file_name"),
                "definition_line": entry.get("definition_line") or entry.get("line_no"),
                "is_definition_found": entry.get("is_definition_found", True),
                "tag": entry.get("tag") or "P",
                "taint_params": taint_params,
            }
            if not summary_only:
                row.update(
                    {
                        "function_description": entry.get("function_description") or task_manager_module._default_entry_function_description(str(entry.get("function_name") or "")),
                        "function_description_source": entry.get("function_description_source") or task_manager_module._entry_description_source(entry.get("function_description")),
                        "entry_reason": entry.get("entry_reason") or task_manager_module._default_entry_reason(entry.get("tag"), str(entry.get("function_name") or "")),
                        "entry_reason_source": entry.get("entry_reason_source") or task_manager_module._entry_description_source(entry.get("entry_reason")),
                        "taint_details": task_manager_module._normalize_entry_taint_details(entry, taint_params),
                        "signature_params": signature_params,
                        "entry_file": entry.get("entry_file"),
                        "source_dir": entry.get("source_dir"),
                    }
                )
            rows.append(row)
        return rows

    def _compact_entry_summary_item_for_db(self: TaskManager, item: dict[str, Any]) -> dict[str, Any]:
        row = dict(item)
        entries = [dict(entry) for entry in row.get("entries") or [] if isinstance(entry, dict)]
        from app.service import task_manager as task_manager_module

        row["entry_count"] = len(entries)
        row["entries_preview"] = self._compact_entry_rows(entries[: task_manager_module.DB_ENTRY_PREVIEW_LIMIT])
        row.pop("entries", None)
        return row

    def _compact_dataflow_summary_item(self: TaskManager, item: dict[str, Any]) -> dict[str, Any]:
        return {
            "entry_key": item.get("entry_key"),
            "firmware_key": item.get("firmware_key"),
            "firmware_name": item.get("firmware_name"),
            "module_key": item.get("module_key"),
            "module_name": item.get("module_name"),
            "file_name": item.get("file_name"),
            "function_name": item.get("function_name"),
            "line_no": item.get("line_no"),
            "entry_file": item.get("entry_file"),
            "source_dir": item.get("source_dir"),
            "module_input_path": item.get("module_input_path"),
            "source_root_path": item.get("source_root_path"),
            "source_file": item.get("source_file") or item.get("definition_file") or item.get("file_name"),
            "artifact_root": item.get("artifact_root"),
            "archive_root": item.get("archive_root"),
            "data_flow_file": item.get("data_flow_file"),
            "data_flow_root": item.get("data_flow_root"),
            "dataflow_dir": item.get("dataflow_dir"),
        }

    def _compact_vuln_summary_item(self: TaskManager, item: dict[str, Any]) -> dict[str, Any]:
        artifact_files = item.get("artifact_files") or []
        return {
            "entry_key": item.get("entry_key"),
            "firmware_key": item.get("firmware_key"),
            "firmware_name": item.get("firmware_name"),
            "module_key": item.get("module_key"),
            "module_name": item.get("module_name"),
            "file_name": item.get("file_name"),
            "function_name": item.get("function_name"),
            "line_no": item.get("line_no"),
            "source_dir": item.get("source_dir"),
            "data_flow_file": item.get("data_flow_file"),
            "dataflow_dir": item.get("dataflow_dir"),
            "workspace_root": item.get("workspace_root"),
            "archive_root": item.get("archive_root"),
            "artifact_file_count": len(artifact_files) if isinstance(artifact_files, list) else 0,
        }
