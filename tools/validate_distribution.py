"""Build and inspect the wheel so every shipped command has its package code."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tomllib
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import cast

from nimrod_simulator.model import JsonObject


class DistributionValidationError(RuntimeError):
    """The built distribution omits source or command modules."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise DistributionValidationError(message)


def source_package_roots(project_root: Path) -> tuple[str, ...]:
    source_root = project_root / "src"
    roots = sorted(
        path.name
        for path in source_root.glob("nimrod_*")
        if path.is_dir() and (path / "__init__.py").is_file()
    )
    require(bool(roots), "No nimrod source packages were found.")
    return tuple(roots)


def configured_package_roots(project_root: Path) -> tuple[str, ...]:
    configuration = tomllib.loads((project_root / "pyproject.toml").read_text(encoding="utf-8"))
    includes = cast(
        list[str],
        configuration["tool"]["setuptools"]["packages"]["find"]["include"],
    )
    roots = tuple(sorted(value.removesuffix("*") for value in includes))
    require(len(roots) == len(set(roots)), "Package discovery contains duplicate roots.")
    return roots


def command_modules(project_root: Path) -> tuple[str, ...]:
    configuration = tomllib.loads((project_root / "pyproject.toml").read_text(encoding="utf-8"))
    scripts = cast(dict[str, str], configuration["project"]["scripts"])
    modules = tuple(sorted({entry_point.split(":", 1)[0] for entry_point in scripts.values()}))
    require(bool(modules), "No distribution commands are configured.")
    return modules


def build_wheel(project_root: Path, wheel_root: Path) -> Path:
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            str(project_root),
            "--no-deps",
            "--wheel-dir",
            str(wheel_root),
        ],
        cwd=project_root,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise DistributionValidationError(
            "Wheel build failed. "
            f"returncode={result.returncode}; stdout={result.stdout!r}; stderr={result.stderr!r}"
        )
    wheels = tuple(wheel_root.glob("*.whl"))
    require(len(wheels) == 1, f"Wheel build produced {len(wheels)} artifacts instead of one.")
    return wheels[0]


def copy_build_source(project_root: Path, destination: Path) -> Path:
    source = destination / "source"
    excluded_names = {
        ".git",
        ".venv",
        "artifacts",
        "build",
        "dist",
        "node_modules",
        "__pycache__",
    }

    def ignore(directory: str, names: list[str]) -> list[str]:
        del directory
        return sorted(
            name
            for name in names
            if name in excluded_names or name.endswith(".egg-info")
        )

    shutil.copytree(project_root, source, ignore=ignore)
    return source


def module_path(module: str) -> str:
    return f"{module.replace('.', '/')}.py"


def inspect_wheel(wheel_path: Path, packages: tuple[str, ...], modules: tuple[str, ...]) -> JsonObject:
    with zipfile.ZipFile(wheel_path) as archive:
        members = set(archive.namelist())
        missing_packages = [name for name in packages if f"{name}/__init__.py" not in members]
        missing_modules = [name for name in modules if module_path(name) not in members]
        entry_point_files = [name for name in members if name.endswith(".dist-info/entry_points.txt")]
    require(not missing_packages, f"Wheel omits source packages: {missing_packages}.")
    require(not missing_modules, f"Wheel entry points reference omitted modules: {missing_modules}.")
    require(len(entry_point_files) == 1, "Wheel must contain exactly one entry_points.txt file.")
    return {
        "wheel_filename": wheel_path.name,
        "source_package_roots": list(packages),
        "source_package_count": len(packages),
        "command_module_count": len(modules),
        "missing_package_count": 0,
        "missing_command_module_count": 0,
        "entry_point_metadata_count": 1,
    }


def validate_distribution(project_root: Path) -> JsonObject:
    packages = source_package_roots(project_root)
    configured = configured_package_roots(project_root)
    require(configured == packages, f"Package discovery differs from source packages: {configured} != {packages}.")
    modules = command_modules(project_root)
    with TemporaryDirectory(prefix="nimrod-distribution-") as temporary:
        temporary_root = Path(temporary)
        build_source = copy_build_source(project_root, temporary_root)
        wheel_path = build_wheel(build_source, temporary_root / "wheels")
        inspection = inspect_wheel(wheel_path, packages, modules)
    return {
        "status": "DISTRIBUTION_WHEEL_CONTENT_VALID",
        "distribution_installation_performed": False,
        "distribution_published": False,
        **inspection,
    }


def main() -> None:
    project_root = Path(__file__).resolve().parent.parent
    result = validate_distribution(project_root)
    report_path = project_root / "reports" / "DISTRIBUTION_VALIDATION.json"
    report_path.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
