"""
EVOLIGHTS-ANCHOR: expose-framework-libs
expose_framework_libs.py
========================

Env-scope shim that makes framework-bundled Arduino libraries (WiFiClientSecure,
HTTPClient, Update, etc.) #include-able from PlatformIO library scopes — most
notably WLED usermods. Without this, a usermod that does

    #include <WiFiClientSecure.h>

fails with "No such file or directory" because PIO compiles each usermod as an
isolated library whose CPPPATH does not see the framework's libraries/<lib>/src
directories.

The companion patch in pio-scripts/load_usermods.py prepends those dirs to each
usermod's per-lib CPPPATH, which works for some PIO versions but proved
fragile. This script does the same job at the *environment* level by injecting
-I<path> into BUILD_FLAGS, so every compile in the env (the main build, the
usermod libs, every other dep) sees the headers.

Belt-and-suspenders: keeping both is intentional. If either one stops working
after a PIO upgrade, the other is the fallback.

Activated only by the EvoLights envs in platformio.ini (see env-evolights
anchor) so it does not affect upstream builds.
EVOLIGHTS-ANCHOR: expose-framework-libs-end
"""

from pathlib import Path
from click import secho

Import("env")  # noqa: F821 — provided by SCons/PIO at script-load time


CANDIDATE_PACKAGES = (
    "framework-arduinoespressif32",
    "framework-arduinoespressif8266",
    "framework-arduino-mbed",
)


def _enumerate_library_include_dirs() -> list[str]:
    """Return [<framework-pkg>/libraries/<lib>/{src or .}] for every bundled lib."""
    pkg_dirs: list[str] = []

    # 1) Ask the platform — works in normal PIO subenvs.
    try:
        platform = env.PioPlatform()  # noqa: F821
        for pkg in CANDIDATE_PACKAGES:
            try:
                p = platform.get_package_dir(pkg)
            except Exception:
                p = None
            if p:
                pkg_dirs.append(p)
    except Exception:
        pass

    # 2) Fallback: walk PROJECT_PACKAGES_DIR.
    if not pkg_dirs:
        try:
            packages_dir = env.subst("$PROJECT_PACKAGES_DIR")  # noqa: F821
        except Exception:
            packages_dir = None
        if packages_dir and Path(packages_dir).is_dir():
            for pkg in CANDIDATE_PACKAGES:
                cand = Path(packages_dir) / pkg
                if cand.is_dir():
                    pkg_dirs.append(str(cand))

    include_dirs: list[str] = []
    for pkg_dir in pkg_dirs:
        libraries_root = Path(pkg_dir) / "libraries"
        if not libraries_root.is_dir():
            continue
        for lib_dir in sorted(libraries_root.iterdir()):
            if not lib_dir.is_dir():
                continue
            src = lib_dir / "src"
            if src.is_dir():
                include_dirs.append(str(src))
                continue
            if any(lib_dir.glob("*.h")):
                include_dirs.append(str(lib_dir))
    return include_dirs


def _apply():
    dirs = _enumerate_library_include_dirs()
    if not dirs:
        secho(
            "expose_framework_libs.py: no framework library include dirs found "
            "(usermods will fail to #include framework headers like "
            "<WiFiClientSecure.h>)",
            fg="yellow",
            err=True,
        )
        return

    # Inject as -I<path> into env CPPPATH AND directly into CCFLAGS / CXXFLAGS.
    #
    # CPPPATH alone is the documented PIO/SCons knob, but PIO's library builder
    # snapshots a lib's compile flags before our usermod CPPPATH tweaks land.
    # Adding -I to *FLAGS makes the include reachable from every compilation
    # unit in this env, including isolated lib subbuilds, with no dependency on
    # SCons env propagation order.
    env.Append(CPPPATH=dirs)  # noqa: F821
    flags = ["-I" + d for d in dirs]
    env.Append(CCFLAGS=flags, CXXFLAGS=flags, ASFLAGS=flags)  # noqa: F821

    # Mention WiFiClientSecure explicitly when it lands so build logs show it.
    has_secure = any(d.endswith(("WiFiClientSecure/src", "WiFiClientSecure\\src"))
                     or Path(d).name == "src" and Path(d).parent.name == "WiFiClientSecure"
                     for d in dirs)
    secho(
        f"expose_framework_libs.py: exposed {len(dirs)} framework library include "
        f"dir(s) to env '{env['PIOENV']}'"  # noqa: F821
        f" (WiFiClientSecure: {'yes' if has_secure else 'NO'})",
        fg="cyan",
        err=True,
    )


_apply()
