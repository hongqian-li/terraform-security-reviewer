"""Discovers and reads .tf files from a given directory path."""

from pathlib import Path


def read_tf_files(path: str) -> dict[str, str]:
    """Recursively scan *path* for .tf files and return {filename: content}.

    Args:
        path: Path to a directory (or a single .tf file) to scan.

    Returns:
        Dictionary mapping each file's path string to its text content.
        Returns an empty dict if no .tf files are found.

    Raises:
        FileNotFoundError: If *path* does not exist.
        PermissionError: If a file or directory cannot be read.
    """
    root = Path(path)

    if not root.exists():
        raise FileNotFoundError(f"Path not found: {path}")

    # Accept a single .tf file directly
    if root.is_file():
        if root.suffix != ".tf":
            raise ValueError(f"Not a .tf file: {path}")
        return {str(root): _read(root)}

    # Directory — recurse
    tf_files = sorted(root.rglob("*.tf"))
    if not tf_files:
        return {}

    result: dict[str, str] = {}
    for tf_file in tf_files:
        result[str(tf_file)] = _read(tf_file)
    return result


def _read(file_path: Path) -> str:
    """Read a single file, propagating PermissionError clearly."""
    try:
        return file_path.read_text(encoding="utf-8")
    except PermissionError:
        raise PermissionError(f"Permission denied: {file_path}")


if __name__ == "__main__":
    import sys

    scan_path = sys.argv[1] if len(sys.argv) > 1 else "."
    print(f"Scanning: {scan_path}\n")

    try:
        files = read_tf_files(scan_path)
    except FileNotFoundError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except PermissionError as e:
        print(f"Error: {e}")
        sys.exit(1)

    if not files:
        print("No .tf files found.")
        sys.exit(0)

    print(f"Found {len(files)} .tf file(s):")
    for name in files:
        print(f"  {name}")
