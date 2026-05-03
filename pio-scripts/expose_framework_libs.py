"""
EVOLIGHTS-ANCHOR: expose-framework-libs
expose_framework_libs.py
========================

Env-scope shim that makes framework-bundled Arduino libraries (WiFiClientSecure,
HTTPClient, Update, etc.) #include-able from PlatformIO library scopes — most
notably WLED usermods. Without this, a usermod that does

    #include <WiFiClientSecure.h>

fails with "No such file or directory" because PIO compiles each usermod as an
isolated library whose CPPPATH does not see the framework's libraries dirs.

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

# Headers we MUST be able to resolve from a usermod compile context. If any of
# these is found anywhere under the framework package, its containing dir is
# added to the env's include path. Catches headers that don't live under the
# canonical libraries/<lib>/src layout (slimmed-down distributions, ESP-IDF
# re-orgs, etc).
REQUIRED_HEADERS = (
    "WiFiClientSecure.h",
    "HTTPClient.h",
    "Update.h",
    "WiFi.h",
    "WiFiClient.h",
)


def _enumerate_library_include_dirs():
    """Return (include_dirs, located).

    include_dirs: deduplicated list of dirs to expose
    located: dict mapping each REQUIRED_HEADERS entry to the list of paths
             where it was found (empty list = MISSING)
    """
    pkg_dirs = []

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

    seen = set()
    include_dirs = []
    located = {h: [] for h in REQUIRED_HEADERS}

    def _add(d):
        s = str(d)
        if s not in seen:
            seen.add(s)
            include_dirs.append(s)

    for pkg_dir in pkg_dirs:
        pkg_path = Path(pkg_dir)

        # Tier A — documented Arduino libraries layout.
        libraries_root = pkg_path / "libraries"
        if libraries_root.is_dir():
            for lib_dir in sorted(libraries_root.iterdir()):
                if not lib_dir.is_dir():
                    continue
                src = lib_dir / "src"
                if src.is_dir():
                    _add(src)
                    continue
                if any(lib_dir.glob("*.h")):
                    _add(lib_dir)

        # Tier B — find REQUIRED headers anywhere under the package and add
        # their containing dir. rglob is O(files) but runs once at configure.
        for header in REQUIRED_HEADERS:
            try:
                for hit in pkg_path.rglob(header):
                    located[header].append(str(hit))
                    _add(hit.parent)
            except Exception:
                pass

    return include_dirs, located


def _apply():
    dirs, located = _enumerate_library_include_dirs()
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

    secho(
        "expose_framework_libs.py: exposed {} framework include dir(s) to env '{}'".format(
            len(dirs), env['PIOENV']  # noqa: F821
        ),
        fg="cyan",
        err=True,
    )
    for header, hits in located.items():
        if hits:
            for h in hits:
                secho("  found {} -> {}".format(header, h), fg="cyan", err=True)
        else:
            secho(
                "  MISSING {} — not found anywhere under framework pkg".format(header),
                fg="yellow",
                err=True,
            )


_apply()
