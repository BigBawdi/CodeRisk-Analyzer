from pathlib import Path


class FileValidationError(Exception):
    """Custom exception for file validation errors."""
    pass


def validate_files(files):
    """
    Validates that the provided files:
    - are not empty
    - exist on disk
    - have .c or .cpp extensions

    Args:
        files (list[str] or str): file path(s)

    Returns:
        list[Path]: validated file paths as Path objects

    Raises:
        FileValidationError: if validation fails
    """

    # Allow single file input
    if isinstance(files, str):
        files = [files]

    if not files:
        raise FileValidationError("No files were provided.")

    valid_extensions = {".c", ".cpp"}
    validated_paths = []

    for file in files:
        path = Path(file)

        # Check existence
        if not path.exists():
            raise FileValidationError(f"File does not exist: {file}")

        # Check extension
        if path.suffix.lower() not in valid_extensions:
            raise FileValidationError(
                f"Invalid file type: {file} (only .c and .cpp allowed)"
            )

        validated_paths.append(path)

    return validated_paths