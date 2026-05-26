from pathlib import Path

from run_vuln_scan import generate_task_md


def _prepare_dataflow_dir(root: Path) -> Path:
    dataflow_dir = root / "dataflow-output"
    dataflow_dir.mkdir(parents=True, exist_ok=True)
    (dataflow_dir / "final_report.md").write_text("# final report\n", encoding="utf-8")
    return dataflow_dir


def test_generate_task_md_includes_files_list_paths(tmp_path: Path) -> None:
    dataflow_dir = _prepare_dataflow_dir(tmp_path)
    source_root = tmp_path / "binary-to-source" / "IPSEC__demo"
    source_root.mkdir(parents=True, exist_ok=True)
    source_c = source_root / "libipsec.c"
    source_h = source_root / "libipsec.h"
    source_c.write_text("int demo(void) { return 0; }\n", encoding="utf-8")
    source_h.write_text("int demo(void);\n", encoding="utf-8")
    manifest_path = source_root / "modules" / "IPSEC" / "files.list"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text("libipsec.c\nlibipsec.h\n", encoding="utf-8")

    task_md = generate_task_md(str(dataflow_dir), str(source_root))

    assert str(manifest_path.resolve()) in task_md
    assert str(source_c.resolve()) in task_md
    assert str(source_h.resolve()) in task_md
    assert "按 `files.list` 解析后的源码文件路径" in task_md
    assert "（来自" not in task_md


def test_generate_task_md_resolves_files_list_entries_relative_to_manifest_dir(tmp_path: Path) -> None:
    dataflow_dir = _prepare_dataflow_dir(tmp_path)
    source_root = tmp_path / "binary-to-source" / "MODULE__demo"
    nested_source = source_root / "modules" / "demo" / "src" / "module.c"
    nested_source.parent.mkdir(parents=True, exist_ok=True)
    nested_source.write_text("int nested(void) { return 1; }\n", encoding="utf-8")
    manifest_path = source_root / "modules" / "demo" / "files.list"
    manifest_path.write_text("src/module.c\n", encoding="utf-8")

    task_md = generate_task_md(str(dataflow_dir), str(source_root))

    assert str(manifest_path.resolve()) in task_md
    assert str(nested_source.resolve()) in task_md
    assert "（来自" not in task_md
