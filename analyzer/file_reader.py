"""Discovers and reads .tf files from a given path."""

from pathlib import Path


def find_tf_files(path: str) -> list[Path]:
    """Recursively find all .tf files under the given path."""
    root = Path(path)
    if not root.exists():
        raise FileNotFoundError(f"Path does not exist: {path}")
    if root.is_file():
        if root.suffix == ".tf":
            return [root]
        raise ValueError(f"File is not a .tf file: {path}")
    return sorted(root.rglob("*.tf"))


def read_tf_file(file_path: Path) -> str:
    """Read and return the contents of a .tf file."""
    return file_path.read_text(encoding="utf-8")
