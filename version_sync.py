#!/usr/bin/env python3
import re
import tomli
import tomli_w
from pathlib import Path
from packaging import version


def sync_versions(init_path: Path, pyproject_path: Path):
    """Sync versions between __init__.py and pyproject.toml, using the greater version"""
    # Read pyproject.toml version
    pyproject = tomli.loads(pyproject_path.read_text())
    pyproject_version = version.parse(pyproject["project"]["version"])
    print(f"{pyproject_path.name} has version v{pyproject_version}")

    # Read __init__.py version
    init_content = init_path.read_text()
    init_match = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', init_content)
    if not init_match:
        raise ValueError("Version not found in __init__.py")

    init_version = version.parse(init_match.group(1))
    print(f"{init_path.name} has version v{init_version}")

    # Use the greater version
    final_version = str(max(init_version, pyproject_version))
    print(f"\n=> using v{final_version}")

    # Update both files
    new_init_content = re.sub(
        r'(__version__\s*=\s*["\'])[^"\']+(["\'])',
        rf"\g<1>{final_version}\g<2>",
        init_content,
    )
    init_path.write_text(new_init_content)

    pyproject["project"]["version"] = final_version
    pyproject_path.write_text(tomli_w.dumps(pyproject))


if __name__ == "__main__":
    root = Path(__file__).parent
    sync_versions(root / "bluep/__init__.py", root / "pyproject.toml")
