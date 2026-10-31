"""
Safe Project ZIP Extraction Subsystem [Role A]:
Provides secure ZIP archive inspection and extraction with defense-in-depth protections
against path traversal (Zip Slip), zip bombs, symlink attacks, UNC/drive targets,
and encrypted/unsupported entries.
"""

import os
import stat
import zipfile
import tempfile
import logging
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, field

logger = logging.getLogger("hdx.ingestion.zip")


class SafeZipError(Exception):
    """Raised when an archive fails security or integrity checks."""
    pass


@dataclass
class SafeZipLimits:
    """Configurable security boundaries for ZIP ingestion."""
    max_archive_size_bytes: int = 50 * 1024 * 1024       # 50 MB
    max_extracted_size_bytes: int = 200 * 1024 * 1024   # 200 MB
    max_file_count: int = 2000                          # Max entries allowed
    max_nesting_depth: int = 15                         # Max folder depth
    max_compression_ratio: float = 100.0               # Max ratio for uncompressed > 1MB
    min_size_for_ratio_check: int = 1024 * 1024         # 1 MB threshold before ratio check


@dataclass
class ExtractionResult:
    """Summary of safe archive extraction."""
    extracted_dir: str
    file_count: int
    total_uncompressed_bytes: int
    extracted_files: List[str] = field(default_factory=list)
    skipped_entries: List[str] = field(default_factory=list)


def _is_link_or_junction(path: str) -> bool:
    """Checks whether path is a symbolic link or Windows reparse point / junction."""
    if os.path.islink(path):
        return True
    try:
        st = os.lstat(path)
        if hasattr(st, "st_reparse_tag") and st.st_reparse_tag != 0:
            return True
    except (OSError, ValueError):
        pass
    return False


class SafeZipExtractor:
    """
    Validates and extracts ZIP archives safely into an isolated directory.
    Enforces path traversal defenses, size quotas, symlink prohibitions, and bomb detection.
    """

    def __init__(self, limits: Optional[SafeZipLimits] = None):
        self.limits = limits or SafeZipLimits()

    def validate_archive(self, zip_path: str) -> None:
        """Performs pre-extraction security analysis on archive header and member list."""
        if not os.path.exists(zip_path):
            raise SafeZipError(f"Archive not found: {zip_path}")

        archive_size = os.path.getsize(zip_path)
        if archive_size > self.limits.max_archive_size_bytes:
            raise SafeZipError(
                f"Archive size {archive_size} exceeds limit of {self.limits.max_archive_size_bytes} bytes"
            )

        if not zipfile.is_zipfile(zip_path):
            raise SafeZipError("File is not a valid ZIP archive")

        with zipfile.ZipFile(zip_path, "r") as zf:
            infolist = zf.infolist()

            if len(infolist) > self.limits.max_file_count:
                raise SafeZipError(
                    f"Archive contains {len(infolist)} entries, exceeding limit of {self.limits.max_file_count}"
                )

            total_extracted = 0
            for info in infolist:
                self._validate_entry_security(info)

                total_extracted += info.file_size
                if total_extracted > self.limits.max_extracted_size_bytes:
                    raise SafeZipError(
                        f"Cumulative extracted size exceeds limit of {self.limits.max_extracted_size_bytes} bytes"
                    )

                # Compression ratio check (zip bomb defense)
                if (
                    info.file_size > self.limits.min_size_for_ratio_check
                    and info.compress_size > 0
                ):
                    ratio = info.file_size / info.compress_size
                    if ratio > self.limits.max_compression_ratio:
                        raise SafeZipError(
                            f"Suspicious compression ratio ({ratio:.1f}:1) detected for entry '{info.filename}'"
                        )

    def _validate_entry_security(self, info: zipfile.ZipInfo) -> None:
        """Inspects an individual ZipInfo entry for dangerous properties."""
        # 1. Encryption check
        if info.flag_bits & 0x1:
            raise SafeZipError(f"Encrypted archive entries are not permitted: '{info.filename}'")

        # 2. Unsupported / non-standard compression methods (0 = stored, 8 = deflated are standard)
        if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            raise SafeZipError(
                f"Unsupported compression method {info.compress_type} for entry: '{info.filename}'"
            )

        # 3. Symlink / Junction / Special file check
        unix_mode = info.external_attr >> 16
        if unix_mode and stat.S_ISLNK(unix_mode):
            raise SafeZipError(f"Symbolic links are strictly rejected: '{info.filename}'")
        if unix_mode and (stat.S_ISCHR(unix_mode) or stat.S_ISBLK(unix_mode) or stat.S_ISFIFO(unix_mode)):
            raise SafeZipError(f"Special device/FIFO files are strictly rejected: '{info.filename}'")

        # 4. Path traversal / absolute path / drive letter / UNC checks
        raw_name = info.filename
        if not raw_name:
            raise SafeZipError("Archive contains an empty filename entry")

        # Normalize slashes for inspection
        normalized = raw_name.replace("\\", "/")

        # Reject UNC paths (//server/share or \\server\share)
        if normalized.startswith("//") or raw_name.startswith("\\\\"):
            raise SafeZipError(f"UNC network paths are rejected: '{raw_name}'")

        # Reject Windows drive letters (e.g. C:, D:) platform-independently
        import re
        if re.match(r"^[a-zA-Z]:", raw_name):
            raise SafeZipError(f"Drive-relative or absolute drive paths are rejected: '{raw_name}'")
        drive, _ = os.path.splitdrive(raw_name)
        if drive:
            raise SafeZipError(f"Drive-relative or absolute drive paths are rejected: '{raw_name}'")

        # Reject absolute paths
        if normalized.startswith("/") or normalized.startswith("\\"):
            raise SafeZipError(f"Absolute paths in archive are rejected: '{raw_name}'")

        # Reject path traversal segments
        parts = normalized.split("/")
        if any(part in ("..", ".") and idx != len(parts) - 1 for idx, part in enumerate(parts)):
            raise SafeZipError(f"Path traversal sequence detected in entry: '{raw_name}'")
        if ".." in parts:
            raise SafeZipError(f"Parent directory traversal '..' detected in entry: '{raw_name}'")

        # Reject excessive directory nesting depth
        # Ignore trailing empty part from directory paths ending with '/'
        depth = len([p for p in parts if p])
        if depth > self.limits.max_nesting_depth:
            raise SafeZipError(
                f"Directory nesting depth ({depth}) exceeds limit of {self.limits.max_nesting_depth} for '{raw_name}'"
            )

    def extract(self, zip_path: str, target_dir: Optional[str] = None) -> ExtractionResult:
        """
        Safely extracts the archive to target_dir (or a created temporary directory).
        Never invokes ZipFile.extractall(). Never follows symlinks or junctions in destination.
        """
        self.validate_archive(zip_path)

        dest_dir = target_dir or tempfile.mkdtemp(prefix="hdx_safe_zip_")
        abs_dest_dir = os.path.abspath(dest_dir)

        # Reject destination if it is itself a symlink or junction
        if _is_link_or_junction(abs_dest_dir):
            raise SafeZipError(f"Extraction destination cannot be a symbolic link or junction: '{abs_dest_dir}'")

        real_dest_dir = os.path.realpath(abs_dest_dir)
        os.makedirs(real_dest_dir, exist_ok=True)

        extracted_files: List[str] = []
        skipped_entries: List[str] = []
        total_bytes = 0
        seen_archive_paths: Set[str] = set()

        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                for info in zf.infolist():
                    # Double-check security of entry metadata
                    self._validate_entry_security(info)

                    # Reject duplicate archive paths
                    entry_norm = info.filename.replace("\\", "/").strip("/")
                    if entry_norm in seen_archive_paths:
                        raise SafeZipError(f"Duplicate archive entry detected: '{info.filename}'")
                    seen_archive_paths.add(entry_norm)

                    clean_rel_path = os.path.normpath(info.filename)
                    # Verify lexical destination stays strictly within abs_dest_dir
                    target_path = os.path.abspath(os.path.join(abs_dest_dir, clean_rel_path))

                    try:
                        common = os.path.commonpath([abs_dest_dir, target_path])
                    except ValueError:
                        raise SafeZipError(
                            f"Extracted path '{target_path}' is outside designated destination '{abs_dest_dir}'"
                        )

                    if common != abs_dest_dir:
                        raise SafeZipError(
                            f"Path traversal detected: '{target_path}' escapes '{abs_dest_dir}'"
                        )

                    # Walk each directory component to ensure no existing component in path is a symlink or junction
                    parts = clean_rel_path.split(os.sep)
                    curr = real_dest_dir
                    for part in parts[:-1]:
                        curr = os.path.join(curr, part)
                        if _is_link_or_junction(curr):
                            raise SafeZipError(
                                f"Symlink traversal detected: path component '{part}' in destination is a link or junction"
                            )
                        # Ensure realpath of intermediate dir does not escape real_dest_dir
                        if os.path.exists(curr):
                            if not os.path.isdir(curr):
                                raise SafeZipError(
                                    f"Path conflict: intermediate component '{curr}' exists and is not a directory"
                                )
                            real_curr = os.path.realpath(curr)
                            if os.path.commonpath([real_dest_dir, real_curr]) != real_dest_dir:
                                raise SafeZipError(
                                    f"Path escape detected: component '{curr}' resolves outside extraction root"
                                )
                        else:
                            os.makedirs(curr, exist_ok=True)

                    # Handle directory entry
                    if info.is_dir():
                        dir_target = os.path.join(real_dest_dir, clean_rel_path)
                        if _is_link_or_junction(dir_target):
                            raise SafeZipError(f"Cannot extract directory over symbolic link or junction: '{clean_rel_path}'")
                        if os.path.lexists(dir_target) and not os.path.isdir(dir_target):
                            raise SafeZipError(f"Directory entry conflicts with existing file: '{clean_rel_path}'")
                        os.makedirs(dir_target, exist_ok=True)
                        continue

                    # Target file validation: Never overwrite or truncate an existing destination file or link
                    final_target = os.path.join(real_dest_dir, clean_rel_path)
                    if _is_link_or_junction(final_target):
                        raise SafeZipError(f"Target file path is an existing symbolic link or junction: '{final_target}'")
                    if os.path.lexists(final_target):
                        raise SafeZipError(f"Destination target file already exists (refusing overwrite/hard-link): '{final_target}'")

                    # Verify realpath of target parent directory does not escape
                    parent_real = os.path.realpath(os.path.dirname(final_target))
                    if os.path.commonpath([real_dest_dir, parent_real]) != real_dest_dir:
                        raise SafeZipError(
                            f"Real destination for '{clean_rel_path}' escapes extraction root: '{parent_real}'"
                        )

                    # Exclusive file creation: Never truncate or overwrite existing files/hard links
                    bytes_written = 0
                    open_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                    if hasattr(os, "O_NOFOLLOW"):
                        open_flags |= os.O_NOFOLLOW

                    try:
                        fd = os.open(final_target, open_flags, 0o644)
                    except (FileExistsError, OSError) as e:
                        raise SafeZipError(f"Safe exclusive file creation failed for '{clean_rel_path}': {e}")

                    with zf.open(info, "r") as src, open(fd, "wb", closefd=True) as dst:
                        while True:
                            chunk = src.read(64 * 1024)
                            if not chunk:
                                break
                            dst.write(chunk)
                            bytes_written += len(chunk)

                    if bytes_written != info.file_size:
                        raise SafeZipError(
                            f"Size mismatch on extraction of '{info.filename}': expected {info.file_size}, got {bytes_written}"
                        )

                    total_bytes += bytes_written
                    extracted_files.append(clean_rel_path)

            return ExtractionResult(
                extracted_dir=abs_dest_dir,
                file_count=len(extracted_files),
                total_uncompressed_bytes=total_bytes,
                extracted_files=extracted_files,
                skipped_entries=skipped_entries
            )
        except Exception:
            # If target_dir was generated internally, cleanup on failure
            if target_dir is None and os.path.exists(abs_dest_dir):
                import shutil
                shutil.rmtree(abs_dest_dir, ignore_errors=True)
            raise


def extract_project_zip(zip_path: str, target_dir: Optional[str] = None, limits: Optional[SafeZipLimits] = None) -> ExtractionResult:
    """Convenience function for safe zip extraction."""
    extractor = SafeZipExtractor(limits=limits)
    return extractor.extract(zip_path, target_dir=target_dir)
