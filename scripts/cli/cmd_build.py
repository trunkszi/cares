"""Configure, inspect and compile CMake targets without hiding cache drift."""

import os
import shutil
from pathlib import Path

import typer

from .build_reuse import verify_build_reuse
from .config import COMPONENTS, PROJECT_ROOT, get_build_directory
from .preset import get_preset_cache_variable, get_preset_compiler, resolve_preset
from .utils import (
    get_concurrency_budget,
    list_ninja_targets,
    prepare_build_environment,
    read_cmake_cache_value,
    should_reconfigure,
)


def _cache_string(value):
    if isinstance(value, bool):
        return "ON" if value else "OFF"
    return str(value)


def _compiler_path(value):
    return Path(shutil.which(str(value)) or value).resolve()


def _expand_preset_text(value):
    if not isinstance(value, str):
        return value
    home = os.environ.get("HOME") or str(Path.home())
    return (
        value.replace("$penv{HOME}", home)
        .replace("$env{HOME}", home)
        .replace("${sourceDir}", str(PROJECT_ROOT))
    )


def _check_cache_drift(build_dir, values):
    cache = Path(build_dir) / "CMakeCache.txt"
    lines = cache.read_text().splitlines() if cache.exists() else []

    def normalize(value):
        if value is None:
            return None
        text = _cache_string(value).upper()
        if text in {"ON", "TRUE", "1", "YES"}:
            return "ON"
        if text in {"OFF", "FALSE", "0", "NO", ""}:
            return "OFF"
        return text

    for key, expected in values.items():
        if expected is None:
            continue
        actual = read_cmake_cache_value(cache, key)
        boolean = isinstance(expected, bool) or any(line.startswith(key + ":BOOL=") for line in lines)
        if boolean:
            if normalize(actual) != normalize(expected):
                return True
        elif key == "CMAKE_CXX_COMPILER":
            if actual is None or _compiler_path(actual) != _compiler_path(expected):
                return True
        elif actual != _cache_string(expected):
            return True
    return False


def ensure_configured(
    preset, out, *, components=None, force_fresh=False, static=None, build_dir=None, extra=None
):
    directory = Path(build_dir or get_build_directory(preset))
    values = {
        name: get_preset_cache_variable(preset, name)
        for name in ["CMAKE_BUILD_TYPE", "CARES_ENABLE_SANITIZERS"]
    }
    compiler = get_preset_compiler(preset)
    if compiler:
        values["CMAKE_CXX_COMPILER"] = compiler
    values.update({COMPONENTS[k]: v for k, v in (components or {}).items()})
    if static is not None:
        values["CMAKE_EXE_LINKER_FLAGS"] = "-static" if static else ""
    values.update(extra or {})
    cache_path = directory / "CMakeCache.txt"
    cached_compiler = read_cmake_cache_value(cache_path, "CMAKE_CXX_COMPILER")
    compiler_changed = bool(
        compiler and cached_compiler and _compiler_path(compiler) != _compiler_path(cached_compiler)
    )
    toolchain = _expand_preset_text(get_preset_cache_variable(preset, "CMAKE_TOOLCHAIN_FILE") or "")
    cached_toolchain = None
    if cache_path.exists():
        cached_toolchain = read_cmake_cache_value(cache_path, "CMAKE_TOOLCHAIN_FILE")
    toolchain_changed = bool(toolchain and cache_path.exists()) and (
        not cached_toolchain or Path(cached_toolchain).resolve() != Path(toolchain).resolve()
    )
    if force_fresh or should_reconfigure(directory) or _check_cache_drift(directory, values) or toolchain_changed:
        command = ["cmake", "--preset", preset, "-B", str(directory)]
        if force_fresh or compiler_changed or toolchain_changed:
            command.append("--fresh")
        command.extend(f"-D{k}={_cache_string(v)}" for k, v in values.items() if v is not None)
        out.run_command(command, env=prepare_build_environment(directory))
    verify_build_reuse(directory)
    return directory


def build_targets(directory, out, targets=None, jobs=None, verbose=False):
    command = ["cmake", "--build", str(directory), "--parallel", str(jobs or get_concurrency_budget())]
    if targets:
        command += ["--target", *targets]
    if verbose or getattr(out, "verbose", False):
        command.append("--verbose")
    out.run_command(command, env=prepare_build_environment(directory))


def build_cmd(
    ctx: typer.Context,
    target: list[str] | None = typer.Option(
        None, "-t", "--target", help="Select a named build, test, or benchmark target"
    ),
    all_targets: bool = typer.Option(False, "--all", help="Select all enabled targets"),
    list_targets: bool = typer.Option(False, "--list", help="List available targets without building"),
    debug: bool = typer.Option(False, "-d", "--debug", help="Use the debug preset"),
    dev: bool = typer.Option(
        False, "-dev", "--dev", "--development", help="Use a development build with sanitizers"
    ),
    compiler: str = typer.Option(
        "clang",
        "-c",
        "--compiler",
        help="Compiler toolchain (clang, gcc, musl-clang, musl-gcc, clang-glibc, gcc-glibc, clang-musl, gcc-musl)",
    ),
    sanitizer: str = typer.Option(
        "asan-ubsan", "-s", "--sanitizer", help="Sanitizer for --dev builds (asan-ubsan)"
    ),
    preset: str | None = typer.Option(
        None,
        "--preset",
        help="Explicit CMake preset override (e.g. clang-glibc-release, gcc-glibc-release, clang-musl-release, gcc-musl-release)",
    ),
    static: bool = typer.Option(False, "--static", help="Link statically with a musl preset"),
    tests: bool = typer.Option(
        True, "--tests/--no-tests", help="Enable or disable tests and native verification tools"
    ),
    bench: bool = typer.Option(False, "--bench", help="Enable benchmark targets"),
    reconfigure: bool = typer.Option(
        False, "-r", "--reconfigure", help="Reconfigure with a fresh CMake cache"
    ),
    clean: bool = typer.Option(
        False, "--clean", help="Remove this preset build directory before configcares"
    ),
    jobs: int | None = typer.Option(
        None, "-j", "--jobs", min=1, help="Maximum parallel build or analysis jobs"
    ),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Show verbose command output"),
):
    """Build all enabled components, or one or more named targets."""
    name = resolve_preset(debug, dev, compiler, sanitizer, preset=preset)
    if static and ("-musl-" not in name or dev or get_preset_cache_variable(name, "CARES_ENABLE_SANITIZERS")):
        raise ValueError("--static requires a musl release/debug preset and cannot be combined with --dev")
    if all_targets and target:
        raise ValueError("Choose --all or --target, not both")
    directory = get_build_directory(name)
    if clean and directory.exists():
        build_root = PROJECT_ROOT.resolve() / "build"
        if (
            (PROJECT_ROOT / "build").is_symlink()
            or directory.is_symlink()
            or directory.resolve().parent != build_root
        ):
            raise ValueError("Refusing to clean a build path outside this checkout")
        shutil.rmtree(directory)
    directory = ensure_configured(
        name,
        ctx.obj,
        components={"tests": tests, "bench": bench},
        force_fresh=reconfigure,
        static=static,
    )
    if list_targets:
        ctx.obj.table("Build targets", ["Target", "Kind"], list_ninja_targets(directory))
        return
    build_targets(directory, ctx.obj, target, jobs, verbose)
