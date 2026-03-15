"""
Tuck Kernel – Core version control for AI session commits.

This module provides a lightweight, filesystem-based version control system
for storing AI conversation commits. It guarantees content-addressable
storage, atomic updates, and safe concurrent access across threads and processes.
"""

import hashlib
import json
import logging
import os
import re
import unicodedata
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from filelock import FileLock, Timeout

logger = logging.getLogger(__name__)


class TuckLockTimeoutError(Exception):
    """Raised when the file lock cannot be acquired within the timeout."""
    pass


class TuckKernel:
    """
    Immutable commit store with branch references.

    Thread-safe and process-safe using a combination of threading.Lock and FileLock.
    """

    GENESIS_COMMIT = "genesis"
    DEFAULT_BRANCH = "main"
    BRANCH_NAME_PATTERN = r"^[a-zA-Z0-9_\-]+$"
    MAX_BRANCH_NAME_LENGTH = 100
    # Allow both real commit hashes and the special "genesis" marker
    COMMIT_ID_PATTERN = r"^([a-f0-9]{64}|genesis)$"

    def __init__(self, vault_dir: str = "~/.tuck_vault") -> None:
        """
        Initialize the kernel repository.

        Args:
            vault_dir: Path to the vault directory (supports ~ expansion).
        """
        self.root = Path(os.path.expanduser(vault_dir)).resolve()
        self.commits = self.root / "commits"
        self.refs = self.root / "refs" / "heads"
        self.lock_file = self.root / "tuck.lock"
        self._thread_lock = threading.Lock()

        # Set secure directory permissions (owner only)
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)

        self.commits.mkdir(parents=True, exist_ok=True)
        self.refs.mkdir(parents=True, exist_ok=True)

        self.head_file = self.root / "HEAD"

        # Initialization is protected by both thread and process locks
        with self._thread_lock:
            try:
                with FileLock(str(self.lock_file), timeout=10):
                    if not self.head_file.exists():
                        self._set_head(self.DEFAULT_BRANCH)
                        self._write_ref(self.DEFAULT_BRANCH, self.GENESIS_COMMIT)
            except Timeout:
                raise TuckLockTimeoutError(
                    "Could not acquire lock to initialize repository"
                )

    # ----------------------------------------------------------------------
    # Internal helpers
    # ----------------------------------------------------------------------

    def _validate_branch_name(self, branch: str) -> None:
        """Raise ValueError if branch name is invalid or unsafe."""
        if not branch or len(branch) > self.MAX_BRANCH_NAME_LENGTH:
            raise ValueError("Invalid branch name length")
        if not re.match(self.BRANCH_NAME_PATTERN, branch):
            raise ValueError(f"Invalid branch name format: {branch}")

    def _validate_commit_id(self, commit_id: str) -> None:
        """Raise ValueError if commit ID is not a valid hash or genesis."""
        if not re.match(self.COMMIT_ID_PATTERN, commit_id):
            raise ValueError(f"Invalid commit ID format: {commit_id}")

    def _set_head(self, branch: str) -> None:
        """Atomically update HEAD to point to the given branch."""
        self._validate_branch_name(branch)
        temp = self.head_file.with_suffix(".tmp")
        # Write with secure permissions
        with open(os.open(temp, os.O_CREAT | os.O_WRONLY, 0o600), "w", encoding="utf-8") as f:
            f.write(branch)
        os.replace(temp, self.head_file)

    def _write_ref(self, branch: str, commit_id: str) -> None:
        """
        Atomically update a branch reference to point to a commit.

        Includes an extra safety check to prevent path traversal attacks.
        """
        self._validate_branch_name(branch)
        self._validate_commit_id(commit_id)

        # Build absolute path and ensure it stays inside refs directory
        ref_path = (self.refs / branch).resolve()
        # Extra safety: verify the resolved path is still under self.refs
        # (handles symlink attacks)
        try:
            ref_path.relative_to(self.refs)
        except ValueError:
            raise ValueError("Security violation: Branch path escape detected")

        temp = ref_path.with_suffix(".tmp")
        # Write with secure permissions
        with open(os.open(temp, os.O_CREAT | os.O_WRONLY, 0o600), "w", encoding="utf-8") as f:
            f.write(commit_id)
        os.replace(temp, ref_path)

    def _canonicalize(self, obj: Any) -> Any:
        """Recursively sort dictionary keys for canonical JSON representation."""
        if isinstance(obj, dict):
            return {k: self._canonicalize(v) for k, v in sorted(obj.items())}
        if isinstance(obj, list):
            return [self._canonicalize(i) for i in obj]
        return obj

    def _normalize_unicode(self, obj: Any) -> Any:
        """Recursively normalize all strings (including dict keys) to NFC."""
        if isinstance(obj, str):
            return unicodedata.normalize("NFC", obj)
        if isinstance(obj, dict):
            return {
                self._normalize_unicode(k): self._normalize_unicode(v)
                for k, v in obj.items()
            }
        if isinstance(obj, list):
            return [self._normalize_unicode(i) for i in obj]
        return obj

    def _compute_commit_id(self, payload: Dict[str, Any]) -> str:
        """
        Compute a deterministic SHA256 hash for a commit payload.

        The payload is normalized (Unicode NFC), canonicalized (dict keys sorted),
        and serialized to a compact JSON string (no extra spaces).
        """
        normalized = self._normalize_unicode(payload)
        canonical = self._canonicalize(normalized)
        # separators=(",", ":") ensures compact JSON without whitespace
        dumped = json.dumps(canonical, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256(dumped.encode("utf-8")).hexdigest()

    # ----------------------------------------------------------------------
    # Public API
    # ----------------------------------------------------------------------

    def get_head(self) -> str:
        """
        Return the current branch name.

        If HEAD file is missing or corrupted, returns DEFAULT_BRANCH.
        """
        if self.head_file.exists():
            try:
                content = self.head_file.read_text(encoding="utf-8").strip()
                if content:
                    return content
            except (OSError, UnicodeDecodeError) as e:
                logger.error("HEAD read failure: %s", e, exc_info=True)
        return self.DEFAULT_BRANCH

    def get_current_commit(self) -> str:
        """
        Return the commit ID that the current HEAD branch points to.

        If the branch reference file is missing or corrupted, returns GENESIS_COMMIT.
        """
        branch = self.get_head()
        ref_path = self.refs / branch
        if ref_path.exists():
            try:
                content = ref_path.read_text(encoding="utf-8").strip()
                if content:
                    return content
            except (OSError, UnicodeDecodeError) as e:
                logger.error("Ref read failure: %s", e, exc_info=True)
        return self.GENESIS_COMMIT

    def commit(
        self,
        messages: List[Dict[str, str]],
        model: str,
        persona_data: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Create a new commit with the given messages, model, and optional persona.

        The commit is written atomically and the current branch is updated to
        point to the new commit. If a commit with the same payload already exists,
        it is reused (no duplicate).

        Returns the commit ID.

        Raises:
            TuckLockTimeoutError: If the file lock cannot be acquired within timeout.
            IOError: If filesystem operations fail.
            ValueError: If input data is invalid.
        """
        payload = {"model": model, "messages": messages, "persona": persona_data}
        commit_id = self._compute_commit_id(payload)

        # Thread lock + process lock for maximum safety
        with self._thread_lock:
            try:
                with FileLock(str(self.lock_file), timeout=10):
                    commit_path = self.commits / f"{commit_id}.json"
                    if not commit_path.exists():
                        data = {
                            "id": commit_id,
                            "parent": self.get_current_commit(),
                            "payload": payload,
                        }
                        temp_path = commit_path.with_suffix(".tmp")
                        try:
                            # Write commit file with secure permissions
                            with open(
                                os.open(temp_path, os.O_CREAT | os.O_WRONLY, 0o600),
                                "w",
                                encoding="utf-8",
                            ) as f:
                                json.dump(data, f, ensure_ascii=False, indent=2)
                            os.replace(temp_path, commit_path)
                        except Exception:
                            # Clean up temporary file on error
                            if temp_path.exists():
                                try:
                                    temp_path.unlink()
                                except OSError as e:
                                    logger.warning(
                                        "Failed to clean up temp file %s: %s",
                                        temp_path, e
                                    )
                            raise

                    self._write_ref(self.get_head(), commit_id)
            except Timeout:
                raise TuckLockTimeoutError(
                    f"Could not acquire lock to commit (timeout 10s)"
                )

        return commit_id
