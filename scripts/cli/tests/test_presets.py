import pytest
from cli.config import COMPILER_ALIASES
from cli.preset import get_preset_cache_variable, load_available_presets, resolve_preset

TOOLCHAINS = ("clang-glibc", "gcc-glibc", "clang-musl", "gcc-musl")
MODES = (
    (False, False, "release", "Release", False),
    (True, False, "debug", "Debug", False),
    (False, True, "asan-ubsan", "Debug", True),
)


def test_public_presets_cover_every_toolchain_mode():
    available = load_available_presets()
    for toolchain in TOOLCHAINS:
        for _debug, _dev, suffix, _build_type, _sanitizers in MODES:
            assert f"{toolchain}-{suffix}" in available
        assert f"{toolchain}-base" not in available


@pytest.mark.parametrize("compiler", ["clang", "gcc", "musl-clang", "musl-gcc"])
@pytest.mark.parametrize(("debug", "dev", "suffix", "build_type", "sanitizers"), MODES)
def test_preset_resolution(compiler, debug, dev, suffix, build_type, sanitizers):
    toolchain = COMPILER_ALIASES[compiler]
    preset = resolve_preset(debug=debug, dev=dev, compiler=compiler)
    assert preset == f"{toolchain}-{suffix}"
    assert get_preset_cache_variable(preset, "CARES_TOOLCHAIN_NAME") == toolchain
    assert get_preset_cache_variable(preset, "CMAKE_BUILD_TYPE") == build_type
    assert get_preset_cache_variable(preset, "CARES_ENABLE_SANITIZERS") is sanitizers
    assert get_preset_cache_variable(preset, "CMAKE_TOOLCHAIN_FILE").endswith(
        "/.vcpkg/scripts/buildsystems/vcpkg.cmake"
    )
    assert get_preset_cache_variable(preset, "VCPKG_CHAINLOAD_TOOLCHAIN_FILE") == (
        f"${{sourceDir}}/cmake/toolchain/{toolchain}.cmake"
    )
    triplet = toolchain
    if suffix == "asan-ubsan" and toolchain in {"clang-glibc", "gcc-glibc"}:
        triplet = f"{toolchain}-asan"
    assert get_preset_cache_variable(preset, "VCPKG_TARGET_TRIPLET") == f"x64-linux-{triplet}"
    assert get_preset_cache_variable(preset, "VCPKG_HOST_TRIPLET") == "x64-linux-gcc-glibc"
    assert get_preset_cache_variable(preset, "VCPKG_OVERLAY_PORTS").endswith("/.local/vcpkg")
    assert get_preset_cache_variable(preset, "VCPKG_OVERLAY_TRIPLETS").endswith("/cmake/triplets")
    assert get_preset_cache_variable(preset, "VCPKG_INSTALLED_DIR") == (
        "${sourceDir}/build/${presetName}/vcpkg_installed"
    )
    assert get_preset_cache_variable(preset, "VCPKG_INSTALL_OPTIONS") == "--no-print-usage"
    if build_type == "Debug":
        assert get_preset_cache_variable(preset, "CMAKE_MAP_IMPORTED_CONFIG_DEBUG") == "Release;None;"
        assert get_preset_cache_variable(preset, "CMAKE_MAP_IMPORTED_CONFIG_RELWITHDEBINFO") == "Release;None;"
    else:
        assert get_preset_cache_variable(preset, "CMAKE_MAP_IMPORTED_CONFIG_DEBUG") is None


def test_explicit_preset_and_conflicts():
    assert resolve_preset(preset="gcc-musl-release") == "gcc-musl-release"
    with pytest.raises(ValueError, match="mutually exclusive"):
        resolve_preset(debug=True, dev=True, compiler="clang")
    with pytest.raises(ValueError, match="Unknown preset"):
        resolve_preset(preset="gcc-glibc-relwithdebinfo")
