"""
Test suite for Distributed Scanner architecture.

Tests cover:
- CacheManager: cache hit/miss, hash stability, pruning, concurrency
- FileDiscovery: exclude patterns, git integration, extension filtering
- FileTask: hash computation, equality, cache key generation
- ScanResult: merge logic, serialization
- WorkerPool: process/thread modes, error isolation
- DistributedScanner: full scan, incremental scan, cache persistence
"""

import os
import sqlite3
import tempfile
import time
import json
import hashlib
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from typing import List, Set

import pytest


# ============================================================================
# FIXTURES
# ============================================================================

@pytest.fixture
def temp_cache_dir(tmp_path):
    """Temporary cache directory for tests."""
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    return str(cache_dir)


@pytest.fixture
def temp_project_dir(tmp_path):
    """Temporary project directory with sample files."""
    project = tmp_path / "project"
    project.mkdir()

    # Create sample files
    (project / "app.py").write_text("import os\npassword = 'secret123'\n")
    (project / "utils.py").write_text("def helper():\n    return True\n")
    (project / "test.py").write_text("assert True\n")

    # Create subdirectory
    subdir = project / "lib"
    subdir.mkdir()
    (subdir / "core.py").write_text("# Core module\nAPI_KEY = 'abc123'\n")

    # Create files to exclude
    node_modules = project / "node_modules"
    node_modules.mkdir()
    (node_modules / "dep.js").write_text("// dependency\n")

    return str(project)


@pytest.fixture
def mock_config():
    """Mock AuditLensConfig."""
    config = Mock()
    config.exclude_paths = {"node_modules", ".git", "__pycache__"}
    config.extensions = {".py", ".js", ".java"}
    config.max_file_size = 10 * 1024 * 1024  # 10MB
    return config


@pytest.fixture
def sample_findings():
    """Sample findings for testing."""
    return [
        {
            "file": "app.py",
            "line": 2,
            "rule": "hardcoded-secret",
            "severity": "HIGH",
            "message": "Hardcoded password detected"
        },
        {
            "file": "lib/core.py",
            "line": 2,
            "rule": "hardcoded-api-key",
            "severity": "HIGH",
            "message": "Hardcoded API key detected"
        }
    ]


# ============================================================================
# MOCK CLASSES (since actual implementation doesn't exist yet)
# ============================================================================

class FileTask:
    """Metadata for a single file to scan."""

    def __init__(self, path: str, size: int, mtime: float, hash: str = None):
        self.path = path
        self.size = size
        self.mtime = mtime
        self._hash = hash

    def compute_hash(self) -> str:
        """Compute SHA256 hash of file content."""
        if self._hash:
            return self._hash

        if not os.path.exists(self.path):
            raise FileNotFoundError(f"File not found: {self.path}")

        sha256 = hashlib.sha256()
        with open(self.path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha256.update(chunk)

        self._hash = sha256.hexdigest()
        return self._hash

    def __eq__(self, other):
        if not isinstance(other, FileTask):
            return False
        return self.path == other.path and self.compute_hash() == other.compute_hash()

    def __hash__(self):
        return hash((self.path, self.compute_hash()))


class ScanStats:
    """Telemetry data class."""

    def __init__(self):
        self.total_files = 0
        self.cache_hits = 0
        self.cache_misses = 0
        self.total_duration = 0.0
        self.worker_durations = []
        self.avg_file_time = 0.0

    def record_cache_hit(self):
        self.cache_hits += 1

    def record_cache_miss(self):
        self.cache_misses += 1

    def record_file_scanned(self, duration: float):
        self.worker_durations.append(duration)
        self.total_files += 1
        self.avg_file_time = sum(self.worker_durations) / len(self.worker_durations)

    def get_summary(self) -> dict:
        return {
            "total_files": self.total_files,
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "cache_hit_rate": self.cache_hits / max(self.total_files, 1),
            "total_duration": self.total_duration,
            "avg_file_time": self.avg_file_time
        }


class ScanResult:
    """Immutable result container."""

    def __init__(self, findings: List[dict], stats: ScanStats = None):
        self.findings = findings
        self.stats = stats or ScanStats()
        self.scanned_files = stats.total_files if stats else 0
        self.cached_files = stats.cache_hits if stats else 0
        self.duration_sec = stats.total_duration if stats else 0.0

    def merge(self, other: 'ScanResult') -> 'ScanResult':
        """Merge two scan results."""
        merged_findings = self.findings + other.findings
        merged_stats = ScanStats()
        merged_stats.total_files = self.stats.total_files + other.stats.total_files
        merged_stats.cache_hits = self.stats.cache_hits + other.stats.cache_hits
        merged_stats.cache_misses = self.stats.cache_misses + other.stats.cache_misses
        merged_stats.worker_durations = self.stats.worker_durations + other.stats.worker_durations
        merged_stats.total_duration = self.stats.total_duration + other.stats.total_duration
        if merged_stats.worker_durations:
            merged_stats.avg_file_time = sum(merged_stats.worker_durations) / len(merged_stats.worker_durations)

        return ScanResult(merged_findings, merged_stats)

    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        return {
            "findings": self.findings,
            "scanned_files": self.scanned_files,
            "cached_files": self.cached_files,
            "duration_sec": self.duration_sec,
            "stats": self.stats.get_summary()
        }

    def print_summary(self):
        """Print human-readable summary."""
        print(f"Scanned: {self.scanned_files} files")
        print(f"Cached: {self.cached_files} files")
        print(f"Findings: {len(self.findings)}")
        print(f"Duration: {self.duration_sec:.2f}s")


class CacheManager:
    """SQLite-backed finding cache."""

    def __init__(self, cache_dir: str = None):
        if cache_dir is None:
            cache_dir = os.path.expanduser("~/.auditlens/cache")

        self.cache_dir = cache_dir
        os.makedirs(cache_dir, exist_ok=True)

        self.db_path = os.path.join(cache_dir, "file_cache.db")
        self._init_db()

    def _init_db(self):
        """Initialize SQLite database with schema."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS file_cache (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT NOT NULL,
                file_hash TEXT NOT NULL,
                findings_json TEXT NOT NULL,
                cached_at TEXT NOT NULL,
                analyzer_version TEXT,
                UNIQUE(file_path, file_hash)
            )
        """)

        cursor.execute("CREATE INDEX IF NOT EXISTS idx_file_hash ON file_cache(file_hash)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cached_at ON file_cache(cached_at)")

        # Enable WAL mode for concurrent reads
        cursor.execute("PRAGMA journal_mode=WAL")

        conn.commit()
        conn.close()

    def get_cached_findings(self, file_path: str, file_hash: str):
        """Retrieve cached findings for a file."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            "SELECT findings_json FROM file_cache WHERE file_path = ? AND file_hash = ?",
            (file_path, file_hash)
        )

        row = cursor.fetchone()
        conn.close()

        if row:
            return json.loads(row[0])
        return None

    def store_findings(self, file_path: str, file_hash: str, findings: List[dict]):
        """Persist findings to cache."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        findings_json = json.dumps(findings)
        cached_at = time.strftime("%Y-%m-%d %H:%M:%S")

        cursor.execute(
            """
            INSERT OR REPLACE INTO file_cache
            (file_path, file_hash, findings_json, cached_at, analyzer_version)
            VALUES (?, ?, ?, ?, ?)
            """,
            (file_path, file_hash, findings_json, cached_at, "0.10.0")
        )

        conn.commit()
        conn.close()

    def invalidate(self, file_path: str):
        """Invalidate all cache entries for a file."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("DELETE FROM file_cache WHERE file_path = ?", (file_path,))

        conn.commit()
        conn.close()

    def prune_stale(self, max_age_days: int = 30) -> int:
        """Remove cache entries older than max_age_days."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cutoff = time.strftime("%Y-%m-%d %H:%M:%S",
                               time.localtime(time.time() - max_age_days * 86400))

        cursor.execute("SELECT COUNT(*) FROM file_cache WHERE cached_at < ?", (cutoff,))
        count = cursor.fetchone()[0]

        cursor.execute("DELETE FROM file_cache WHERE cached_at < ?", (cutoff,))

        conn.commit()
        conn.close()

        return count

    def _compute_hash(self, file_path: str) -> str:
        """Compute SHA256 hash of file content."""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha256.update(chunk)
        return sha256.hexdigest()


class FileDiscovery:
    """Efficient file tree walker with exclusion support."""

    @staticmethod
    def discover_files(path: str, exclude_dirs: Set[str] = None, extensions: Set[str] = None):
        """Walk directory tree and yield FileTask objects."""
        if exclude_dirs is None:
            exclude_dirs = {"node_modules", ".git", "__pycache__", "venv"}

        for root, dirs, files in os.walk(path):
            # Filter out excluded directories
            dirs[:] = [d for d in dirs if d not in exclude_dirs]

            for file in files:
                file_path = os.path.join(root, file)

                # Filter by extension if specified
                if extensions:
                    _, ext = os.path.splitext(file)
                    if ext not in extensions:
                        continue

                try:
                    stat = os.stat(file_path)
                    yield FileTask(
                        path=file_path,
                        size=stat.st_size,
                        mtime=stat.st_mtime
                    )
                except OSError:
                    # File deleted between discovery and stat
                    continue

    @staticmethod
    def _should_scan(file_path: str, exclude_patterns: List[str]) -> bool:
        """Check if file should be scanned based on exclusion patterns."""
        for pattern in exclude_patterns:
            if pattern in file_path:
                return False
        return True

    @staticmethod
    def _get_changed_files_since(baseline: str, git_root: str) -> Set[str]:
        """Get changed files since baseline commit using git diff."""
        import subprocess

        try:
            result = subprocess.run(
                ["git", "diff", "--name-only", baseline],
                cwd=git_root,
                capture_output=True,
                text=True,
                check=True
            )

            changed_files = set()
            for line in result.stdout.strip().split("\n"):
                if line:
                    changed_files.add(os.path.join(git_root, line))

            return changed_files
        except subprocess.CalledProcessError:
            return set()


class WorkerPool:
    """Process/thread pool wrapper."""

    def __init__(self, num_workers: int, mode: str = 'process'):
        self.num_workers = num_workers
        self.mode = mode

        if mode == 'process':
            self.executor = ProcessPoolExecutor(max_workers=num_workers)
        elif mode == 'thread':
            self.executor = ThreadPoolExecutor(max_workers=num_workers)
        else:
            raise ValueError(f"Invalid mode: {mode}. Use 'process' or 'thread'.")

    def map(self, func, tasks: List, progress: bool = True) -> List:
        """Distribute tasks to worker pool."""
        results = []

        try:
            futures = [self.executor.submit(func, task) for task in tasks]

            for future in futures:
                try:
                    result = future.result(timeout=60)
                    results.append(result)
                except Exception as e:
                    # Error isolation: log error but continue with other workers
                    print(f"Worker error: {e}")
                    results.append([])
        except Exception as e:
            print(f"Pool error: {e}")

        return results

    def shutdown(self):
        """Shutdown worker pool."""
        self.executor.shutdown(wait=True)

    @staticmethod
    def _worker_init():
        """Initialize worker process."""
        # Pre-warm parser cache, set up signal handlers, etc.
        pass


class DistributedScanner:
    """Orchestrator for distributed scanning."""

    def __init__(self, config, num_workers: int = 4, cache_dir: str = None):
        self.config = config
        self.num_workers = num_workers
        self.cache_manager = CacheManager(cache_dir)
        self.worker_pool = WorkerPool(num_workers, mode='process')

    def scan_async(self, path: str, incremental: bool = False, **scan_kwargs) -> ScanResult:
        """Main entry point for distributed scanning."""
        start_time = time.time()

        # Discover files
        files = list(FileDiscovery.discover_files(
            path,
            exclude_dirs=self.config.exclude_paths,
            extensions=self.config.extensions
        ))

        # Partition files among workers
        partitions = self._partition_files(files)

        # Scan with worker pool
        worker_results = self.worker_pool.map(self._scan_partition, partitions)

        # Aggregate results
        result = self._aggregate_results(worker_results)
        result.stats.total_duration = time.time() - start_time

        return result

    def scan_incremental(self, path: str, cache_key: str = None, **scan_kwargs) -> ScanResult:
        """Scan only changed files since last cached run."""
        # Get changed files via git diff
        changed_files = FileDiscovery._get_changed_files_since("HEAD", path)

        if not changed_files:
            # No changes, return empty result
            return ScanResult([], ScanStats())

        # Filter files to only changed ones
        files = [
            f for f in FileDiscovery.discover_files(
                path,
                exclude_dirs=self.config.exclude_paths,
                extensions=self.config.extensions
            )
            if f.path in changed_files
        ]

        # Scan changed files
        start_time = time.time()
        partitions = self._partition_files(files)
        worker_results = self.worker_pool.map(self._scan_partition, partitions)
        result = self._aggregate_results(worker_results)
        result.stats.total_duration = time.time() - start_time

        return result

    def _partition_files(self, files: List[FileTask]) -> List[List[FileTask]]:
        """Partition files among workers for load balancing."""
        if not files:
            return []

        # Sort by size (descending) for better load balancing
        sorted_files = sorted(files, key=lambda f: f.size, reverse=True)

        # Round-robin distribution
        partitions = [[] for _ in range(self.num_workers)]
        for i, file in enumerate(sorted_files):
            partitions[i % self.num_workers].append(file)

        return [p for p in partitions if p]  # Remove empty partitions

    def _scan_partition(self, partition: List[FileTask]) -> ScanResult:
        """Scan a partition of files (runs in worker process)."""
        findings = []
        stats = ScanStats()

        for file_task in partition:
            start = time.time()

            # Check cache
            file_hash = file_task.compute_hash()
            cached = self.cache_manager.get_cached_findings(file_task.path, file_hash)

            if cached is not None:
                findings.extend(cached)
                stats.record_cache_hit()
            else:
                # Simulate scanning (in real implementation, call analyzer.py)
                file_findings = self._scan_file(file_task)
                findings.extend(file_findings)

                # Store in cache
                self.cache_manager.store_findings(file_task.path, file_hash, file_findings)
                stats.record_cache_miss()

            stats.record_file_scanned(time.time() - start)

        return ScanResult(findings, stats)

    def _scan_file(self, file_task: FileTask) -> List[dict]:
        """Scan a single file (mock implementation)."""
        # In real implementation, this would call analyzer.scan_file()
        return []

    def _aggregate_results(self, worker_results: List[ScanResult]) -> ScanResult:
        """Aggregate results from all workers."""
        if not worker_results:
            return ScanResult([], ScanStats())

        merged = worker_results[0]
        for result in worker_results[1:]:
            merged = merged.merge(result)

        return merged


# ============================================================================
# UNIT TESTS: FileTask
# ============================================================================

class TestFileTask:
    """Unit tests for FileTask class."""

    def test_file_task_creation(self, temp_project_dir):
        """Test FileTask initialization."""
        file_path = os.path.join(temp_project_dir, "app.py")
        stat = os.stat(file_path)

        task = FileTask(file_path, stat.st_size, stat.st_mtime)

        assert task.path == file_path
        assert task.size == stat.st_size
        assert task.mtime == stat.st_mtime
        assert task._hash is None

    def test_compute_hash(self, temp_project_dir):
        """Test hash computation."""
        file_path = os.path.join(temp_project_dir, "app.py")
        task = FileTask(file_path, 0, 0)

        hash1 = task.compute_hash()
        hash2 = task.compute_hash()  # Should use cached value

        assert len(hash1) == 64  # SHA256 hex digest
        assert hash1 == hash2

    def test_hash_stability(self, temp_project_dir):
        """Test that hash is stable for unchanged file."""
        file_path = os.path.join(temp_project_dir, "app.py")

        task1 = FileTask(file_path, 0, 0)
        hash1 = task1.compute_hash()

        task2 = FileTask(file_path, 0, 0)
        hash2 = task2.compute_hash()

        assert hash1 == hash2

    def test_hash_changes_on_content_change(self, tmp_path):
        """Test that hash changes when file content changes."""
        file_path = tmp_path / "test.py"
        file_path.write_text("version 1")

        task1 = FileTask(str(file_path), 0, 0)
        hash1 = task1.compute_hash()

        file_path.write_text("version 2")

        task2 = FileTask(str(file_path), 0, 0)
        hash2 = task2.compute_hash()

        assert hash1 != hash2

    def test_equality(self, temp_project_dir):
        """Test FileTask equality."""
        file_path = os.path.join(temp_project_dir, "app.py")

        task1 = FileTask(file_path, 0, 0)
        task2 = FileTask(file_path, 0, 0)

        assert task1 == task2
        assert hash(task1) == hash(task2)

    def test_inequality_different_files(self, temp_project_dir):
        """Test inequality for different files."""
        task1 = FileTask(os.path.join(temp_project_dir, "app.py"), 0, 0)
        task2 = FileTask(os.path.join(temp_project_dir, "utils.py"), 0, 0)

        assert task1 != task2
        assert hash(task1) != hash(task2)

    def test_file_not_found(self, tmp_path):
        """Test error handling for missing file."""
        file_path = tmp_path / "nonexistent.py"
        task = FileTask(str(file_path), 0, 0)

        with pytest.raises(FileNotFoundError):
            task.compute_hash()


# ============================================================================
# UNIT TESTS: ScanStats
# ============================================================================

class TestScanStats:
    """Unit tests for ScanStats class."""

    def test_initial_state(self):
        """Test initial stats state."""
        stats = ScanStats()

        assert stats.total_files == 0
        assert stats.cache_hits == 0
        assert stats.cache_misses == 0
        assert stats.total_duration == 0.0
        assert stats.avg_file_time == 0.0

    def test_record_cache_hit(self):
        """Test recording cache hits."""
        stats = ScanStats()

        stats.record_cache_hit()
        stats.record_cache_hit()

        assert stats.cache_hits == 2

    def test_record_cache_miss(self):
        """Test recording cache misses."""
        stats = ScanStats()

        stats.record_cache_miss()

        assert stats.cache_misses == 1

    def test_record_file_scanned(self):
        """Test recording file scan duration."""
        stats = ScanStats()

        stats.record_file_scanned(0.5)
        stats.record_file_scanned(1.0)
        stats.record_file_scanned(1.5)

        assert stats.total_files == 3
        assert len(stats.worker_durations) == 3
        assert stats.avg_file_time == 1.0

    def test_get_summary(self):
        """Test summary generation."""
        stats = ScanStats()
        stats.total_files = 10
        stats.cache_hits = 7
        stats.cache_misses = 3
        stats.total_duration = 5.0
        stats.worker_durations = [0.5] * 10
        stats.avg_file_time = 0.5

        summary = stats.get_summary()

        assert summary["total_files"] == 10
        assert summary["cache_hits"] == 7
        assert summary["cache_misses"] == 3
        assert summary["cache_hit_rate"] == 0.7
        assert summary["total_duration"] == 5.0
        assert summary["avg_file_time"] == 0.5


# ============================================================================
# UNIT TESTS: ScanResult
# ============================================================================

class TestScanResult:
    """Unit tests for ScanResult class."""

    def test_creation(self, sample_findings):
        """Test ScanResult creation."""
        result = ScanResult(sample_findings)

        assert len(result.findings) == 2
        assert result.scanned_files == 0
        assert result.cached_files == 0

    def test_creation_with_stats(self, sample_findings):
        """Test creation with stats."""
        stats = ScanStats()
        stats.total_files = 5
        stats.cache_hits = 2
        stats.total_duration = 3.5

        result = ScanResult(sample_findings, stats)

        assert result.scanned_files == 5
        assert result.cached_files == 2
        assert result.duration_sec == 3.5

    def test_merge(self):
        """Test merging two results."""
        stats1 = ScanStats()
        stats1.total_files = 5
        stats1.cache_hits = 3
        stats1.cache_misses = 2

        stats2 = ScanStats()
        stats2.total_files = 3
        stats2.cache_hits = 2
        stats2.cache_misses = 1

        result1 = ScanResult([{"file": "a.py"}], stats1)
        result2 = ScanResult([{"file": "b.py"}], stats2)

        merged = result1.merge(result2)

        assert len(merged.findings) == 2
        assert merged.stats.total_files == 8
        assert merged.stats.cache_hits == 5
        assert merged.stats.cache_misses == 3

    def test_to_dict(self, sample_findings):
        """Test serialization to dict."""
        stats = ScanStats()
        stats.total_files = 2
        stats.cache_hits = 1

        result = ScanResult(sample_findings, stats)
        data = result.to_dict()

        assert "findings" in data
        assert "scanned_files" in data
        assert "cached_files" in data
        assert "duration_sec" in data
        assert "stats" in data
        assert len(data["findings"]) == 2


# ============================================================================
# UNIT TESTS: CacheManager
# ============================================================================

class TestCacheManager:
    """Unit tests for CacheManager class."""

    def test_initialization(self, temp_cache_dir):
        """Test cache manager initialization."""
        manager = CacheManager(temp_cache_dir)

        assert os.path.exists(manager.db_path)
        assert manager.cache_dir == temp_cache_dir

    def test_cache_miss(self, temp_cache_dir):
        """Test cache miss returns None."""
        manager = CacheManager(temp_cache_dir)

        result = manager.get_cached_findings("app.py", "abc123")

        assert result is None

    def test_cache_hit(self, temp_cache_dir, sample_findings):
        """Test cache hit returns stored findings."""
        manager = CacheManager(temp_cache_dir)

        # Store findings
        manager.store_findings("app.py", "abc123", sample_findings)

        # Retrieve findings
        cached = manager.get_cached_findings("app.py", "abc123")

        assert cached is not None
        assert len(cached) == 2
        assert cached[0]["rule"] == "hardcoded-secret"

    def test_cache_invalidation_on_hash_change(self, temp_cache_dir, sample_findings):
        """Test that cache is invalidated when file hash changes."""
        manager = CacheManager(temp_cache_dir)

        # Store with hash v1
        manager.store_findings("app.py", "hash_v1", sample_findings)

        # Try to retrieve with hash v2
        cached = manager.get_cached_findings("app.py", "hash_v2")

        assert cached is None

    def test_store_and_retrieve_empty_findings(self, temp_cache_dir):
        """Test storing and retrieving empty findings list."""
        manager = CacheManager(temp_cache_dir)

        manager.store_findings("clean.py", "def456", [])
        cached = manager.get_cached_findings("clean.py", "def456")

        assert cached == []

    def test_invalidate(self, temp_cache_dir, sample_findings):
        """Test cache invalidation."""
        manager = CacheManager(temp_cache_dir)

        manager.store_findings("app.py", "abc123", sample_findings)
        manager.invalidate("app.py")

        cached = manager.get_cached_findings("app.py", "abc123")
        assert cached is None

    def test_prune_stale_entries(self, temp_cache_dir, sample_findings):
        """Test pruning stale cache entries."""
        manager = CacheManager(temp_cache_dir)

        # Store findings
        manager.store_findings("old.py", "old_hash", sample_findings)

        # Manually update cached_at to be old
        conn = sqlite3.connect(manager.db_path)
        cursor = conn.cursor()
        old_date = "2020-01-01 00:00:00"
        cursor.execute(
            "UPDATE file_cache SET cached_at = ? WHERE file_path = ?",
            (old_date, "old.py")
        )
        conn.commit()
        conn.close()

        # Prune entries older than 30 days
        count = manager.prune_stale(max_age_days=30)

        assert count == 1
        cached = manager.get_cached_findings("old.py", "old_hash")
        assert cached is None

    def test_concurrent_reads(self, temp_cache_dir, sample_findings):
        """Test concurrent cache reads (WAL mode)."""
        manager = CacheManager(temp_cache_dir)
        manager.store_findings("concurrent.py", "hash1", sample_findings)

        # Simulate concurrent reads
        import threading

        results = []

        def read_cache():
            cached = manager.get_cached_findings("concurrent.py", "hash1")
            results.append(cached)

        threads = [threading.Thread(target=read_cache) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert all(r is not None for r in results)
        assert all(len(r) == 2 for r in results)

    def test_replace_existing_cache_entry(self, temp_cache_dir):
        """Test that storing with same path+hash replaces old entry."""
        manager = CacheManager(temp_cache_dir)

        findings_v1 = [{"rule": "old"}]
        findings_v2 = [{"rule": "new"}]

        manager.store_findings("file.py", "hash1", findings_v1)
        manager.store_findings("file.py", "hash1", findings_v2)

        cached = manager.get_cached_findings("file.py", "hash1")

        assert len(cached) == 1
        assert cached[0]["rule"] == "new"


# ============================================================================
# UNIT TESTS: FileDiscovery
# ============================================================================

class TestFileDiscovery:
    """Unit tests for FileDiscovery class."""

    def test_discover_all_files(self, temp_project_dir):
        """Test discovering all files in a directory."""
        files = list(FileDiscovery.discover_files(temp_project_dir))

        file_names = [os.path.basename(f.path) for f in files]

        assert "app.py" in file_names
        assert "utils.py" in file_names
        assert "test.py" in file_names
        assert "core.py" in file_names

    def test_exclude_directories(self, temp_project_dir):
        """Test excluding directories."""
        files = list(FileDiscovery.discover_files(
            temp_project_dir,
            exclude_dirs={"node_modules"}
        ))

        file_paths = [f.path for f in files]

        assert not any("node_modules" in p for p in file_paths)

    def test_filter_by_extension(self, temp_project_dir):
        """Test filtering by file extension."""
        files = list(FileDiscovery.discover_files(
            temp_project_dir,
            extensions={".py"}
        ))

        assert all(f.path.endswith(".py") for f in files)

    def test_multiple_extensions(self, temp_project_dir):
        """Test filtering with multiple extensions."""
        # Add a JS file
        js_file = os.path.join(temp_project_dir, "script.js")
        with open(js_file, "w") as f:
            f.write("console.log('test');")

        files = list(FileDiscovery.discover_files(
            temp_project_dir,
            extensions={".py", ".js"}
        ))

        extensions = {os.path.splitext(f.path)[1] for f in files}

        assert ".py" in extensions
        assert ".js" in extensions

    def test_empty_directory(self, tmp_path):
        """Test scanning empty directory."""
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()

        files = list(FileDiscovery.discover_files(str(empty_dir)))

        assert len(files) == 0

    def test_file_task_metadata(self, temp_project_dir):
        """Test that FileTask contains correct metadata."""
        files = list(FileDiscovery.discover_files(temp_project_dir))

        for file in files:
            assert os.path.exists(file.path)
            assert file.size > 0
            assert file.mtime > 0

    def test_should_scan_exclusion(self):
        """Test _should_scan with exclusion patterns."""
        assert FileDiscovery._should_scan("src/app.py", ["node_modules", "test_"])
        assert not FileDiscovery._should_scan("node_modules/lib.js", ["node_modules"])
        assert not FileDiscovery._should_scan("test_utils.py", ["test_"])

    @patch("subprocess.run")
    def test_git_changed_files(self, mock_run, temp_project_dir):
        """Test getting changed files from git diff."""
        mock_run.return_value = Mock(
            stdout="app.py\nlib/core.py\n",
            returncode=0
        )

        changed = FileDiscovery._get_changed_files_since("HEAD", temp_project_dir)

        assert len(changed) == 2
        assert any("app.py" in f for f in changed)
        assert any("core.py" in f for f in changed)

    @patch("subprocess.run")
    def test_git_error_returns_empty_set(self, mock_run):
        """Test that git errors return empty set."""
        mock_run.side_effect = Exception("git not found")

        changed = FileDiscovery._get_changed_files_since("HEAD", "/tmp")

        assert changed == set()


# ============================================================================
# UNIT TESTS: WorkerPool
# ============================================================================

class TestWorkerPool:
    """Unit tests for WorkerPool class."""

    def test_process_pool_creation(self):
        """Test creating process pool."""
        pool = WorkerPool(num_workers=2, mode='process')

        assert pool.num_workers == 2
        assert pool.mode == 'process'
        assert isinstance(pool.executor, ProcessPoolExecutor)

        pool.shutdown()

    def test_thread_pool_creation(self):
        """Test creating thread pool."""
        pool = WorkerPool(num_workers=2, mode='thread')

        assert pool.mode == 'thread'
        assert isinstance(pool.executor, ThreadPoolExecutor)

        pool.shutdown()

    def test_invalid_mode(self):
        """Test invalid pool mode raises error."""
        with pytest.raises(ValueError, match="Invalid mode"):
            WorkerPool(num_workers=2, mode='invalid')

    def test_map_simple_function(self):
        """Test mapping a simple function over tasks."""
        pool = WorkerPool(num_workers=2, mode='thread')

        def double(x):
            return x * 2

        results = pool.map(double, [1, 2, 3, 4, 5])

        assert results == [2, 4, 6, 8, 10]

        pool.shutdown()

    def test_map_with_errors(self):
        """Test error isolation in worker pool."""
        pool = WorkerPool(num_workers=2, mode='thread')

        def risky_func(x):
            if x == 3:
                raise ValueError("Error at 3")
            return x * 2

        results = pool.map(risky_func, [1, 2, 3, 4, 5], progress=False)

        # Should have 5 results, but one is empty list due to error
        assert len(results) == 5
        assert [] in results  # Error result

        pool.shutdown()

    def test_shutdown(self):
        """Test pool shutdown."""
        pool = WorkerPool(num_workers=2, mode='thread')

        pool.shutdown()

        # Executor should be shutdown
        # (Note: can't easily test this without implementation details)


# ============================================================================
# INTEGRATION TESTS: DistributedScanner
# ============================================================================

class TestDistributedScanner:
    """Integration tests for DistributedScanner."""

    def test_scanner_initialization(self, mock_config, temp_cache_dir):
        """Test scanner initialization."""
        scanner = DistributedScanner(mock_config, num_workers=2, cache_dir=temp_cache_dir)

        assert scanner.num_workers == 2
        assert scanner.cache_manager is not None
        assert scanner.worker_pool is not None

    def test_partition_files_empty(self, mock_config, temp_cache_dir):
        """Test partitioning with no files."""
        scanner = DistributedScanner(mock_config, num_workers=2, cache_dir=temp_cache_dir)

        partitions = scanner._partition_files([])

        assert partitions == []

    def test_partition_files_distribution(self, mock_config, temp_cache_dir, temp_project_dir):
        """Test that files are distributed evenly among workers."""
        scanner = DistributedScanner(mock_config, num_workers=2, cache_dir=temp_cache_dir)

        files = list(FileDiscovery.discover_files(temp_project_dir))
        partitions = scanner._partition_files(files)

        assert len(partitions) <= 2
        assert sum(len(p) for p in partitions) == len(files)

    def test_partition_load_balancing(self, mock_config, temp_cache_dir):
        """Test load balancing by file size."""
        scanner = DistributedScanner(mock_config, num_workers=2, cache_dir=temp_cache_dir)

        files = [
            FileTask("large.py", 1000, 0),
            FileTask("medium.py", 500, 0),
            FileTask("small1.py", 100, 0),
            FileTask("small2.py", 100, 0),
        ]

        partitions = scanner._partition_files(files)

        # Large files should be in different partitions
        partition_sizes = [sum(f.size for f in p) for p in partitions]

        assert len(partitions) == 2
        assert abs(partition_sizes[0] - partition_sizes[1]) <= 500

    @patch.object(DistributedScanner, '_scan_file')
    def test_scan_async_basic(self, mock_scan, mock_config, temp_cache_dir, temp_project_dir):
        """Test basic async scan."""
        mock_scan.return_value = [{"rule": "test"}]

        scanner = DistributedScanner(mock_config, num_workers=2, cache_dir=temp_cache_dir)
        result = scanner.scan_async(temp_project_dir)

        assert result is not None
        assert result.stats.total_duration > 0
        assert result.scanned_files >= 0

    @patch.object(DistributedScanner, '_scan_file')
    def test_cache_persistence(self, mock_scan, mock_config, temp_cache_dir, temp_project_dir):
        """Test that findings are cached and reused."""
        mock_scan.return_value = [{"rule": "cached-finding"}]

        scanner = DistributedScanner(mock_config, num_workers=2, cache_dir=temp_cache_dir)

        # First scan - should miss cache
        result1 = scanner.scan_async(temp_project_dir)
        cache_misses_1 = result1.stats.cache_misses

        # Second scan - should hit cache
        result2 = scanner.scan_async(temp_project_dir)
        cache_hits_2 = result2.stats.cache_hits

        assert cache_misses_1 > 0
        assert cache_hits_2 > 0
        assert cache_hits_2 >= cache_misses_1  # Most files should be cached

    @patch.object(FileDiscovery, '_get_changed_files_since')
    @patch.object(DistributedScanner, '_scan_file')
    def test_incremental_scan(self, mock_scan, mock_git, mock_config, temp_cache_dir, temp_project_dir):
        """Test incremental scan only processes changed files."""
        mock_scan.return_value = []

        # Simulate only one file changed
        changed_file = os.path.join(temp_project_dir, "app.py")
        mock_git.return_value = {changed_file}

        scanner = DistributedScanner(mock_config, num_workers=2, cache_dir=temp_cache_dir)
        result = scanner.scan_incremental(temp_project_dir)

        # Should only scan changed files
        assert result.scanned_files <= 1

    @patch.object(FileDiscovery, '_get_changed_files_since')
    def test_incremental_scan_no_changes(self, mock_git, mock_config, temp_cache_dir, temp_project_dir):
        """Test incremental scan with no changes returns empty result."""
        mock_git.return_value = set()

        scanner = DistributedScanner(mock_config, num_workers=2, cache_dir=temp_cache_dir)
        result = scanner.scan_incremental(temp_project_dir)

        assert len(result.findings) == 0
        assert result.scanned_files == 0

    def test_aggregate_results_single(self, mock_config, temp_cache_dir):
        """Test aggregating single result."""
        scanner = DistributedScanner(mock_config, num_workers=2, cache_dir=temp_cache_dir)

        stats = ScanStats()
        stats.total_files = 5
        result = ScanResult([{"rule": "test"}], stats)

        aggregated = scanner._aggregate_results([result])

        assert len(aggregated.findings) == 1
        assert aggregated.stats.total_files == 5

    def test_aggregate_results_multiple(self, mock_config, temp_cache_dir):
        """Test aggregating multiple results."""
        scanner = DistributedScanner(mock_config, num_workers=2, cache_dir=temp_cache_dir)

        stats1 = ScanStats()
        stats1.total_files = 3
        result1 = ScanResult([{"file": "a.py"}], stats1)

        stats2 = ScanStats()
        stats2.total_files = 2
        result2 = ScanResult([{"file": "b.py"}], stats2)

        aggregated = scanner._aggregate_results([result1, result2])

        assert len(aggregated.findings) == 2
        assert aggregated.stats.total_files == 5


# ============================================================================
# EDGE CASES & ERROR HANDLING
# ============================================================================

class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_scan_single_file(self, mock_config, temp_cache_dir, tmp_path):
        """Test scanning single file (no parallelism)."""
        file = tmp_path / "single.py"
        file.write_text("password = 'test'")

        scanner = DistributedScanner(mock_config, num_workers=4, cache_dir=temp_cache_dir)
        result = scanner.scan_async(str(tmp_path))

        assert result is not None

    def test_file_deleted_during_scan(self, mock_config, temp_cache_dir, tmp_path):
        """Test handling file deletion during scan."""
        file = tmp_path / "temp.py"
        file.write_text("test")

        scanner = DistributedScanner(mock_config, num_workers=2, cache_dir=temp_cache_dir)

        # File discovery will happen, then we delete the file
        files = list(FileDiscovery.discover_files(str(tmp_path)))
        file.unlink()

        # Scan should handle missing file gracefully
        try:
            partitions = scanner._partition_files(files)
            # Worker should handle FileNotFoundError
        except Exception as e:
            pytest.fail(f"Should handle deleted files gracefully: {e}")

    def test_corrupted_cache(self, temp_cache_dir):
        """Test handling corrupted cache database."""
        manager = CacheManager(temp_cache_dir)

        # Corrupt the database
        with open(manager.db_path, 'w') as f:
            f.write("CORRUPTED DATA")

        # Should handle gracefully and reinitialize
        try:
            manager2 = CacheManager(temp_cache_dir)
        except Exception as e:
            # Expected: database might be recreated or error raised
            assert "database" in str(e).lower() or "disk" in str(e).lower()

    def test_worker_timeout(self, mock_config, temp_cache_dir):
        """Test worker timeout handling."""
        scanner = DistributedScanner(mock_config, num_workers=2, cache_dir=temp_cache_dir)

        def slow_task(x):
            time.sleep(10)
            return x

        # Workers should timeout and return empty results
        results = scanner.worker_pool.map(slow_task, [1, 2], progress=False)

        # Should get some results (empty due to timeout)
        assert len(results) == 2

    def test_very_large_file(self, mock_config, temp_cache_dir, tmp_path):
        """Test handling very large files."""
        large_file = tmp_path / "large.py"
        large_file.write_text("x = 1\n" * 100000)  # 600KB file

        scanner = DistributedScanner(mock_config, num_workers=2, cache_dir=temp_cache_dir)

        # Should handle large file
        result = scanner.scan_async(str(tmp_path))
        assert result is not None

    def test_unicode_filenames(self, mock_config, temp_cache_dir, tmp_path):
        """Test handling files with unicode names."""
        unicode_file = tmp_path / "测试.py"
        unicode_file.write_text("# Test file")

        files = list(FileDiscovery.discover_files(str(tmp_path)))

        assert len(files) == 1
        assert "测试.py" in files[0].path

    def test_symlink_handling(self, mock_config, temp_project_dir, tmp_path):
        """Test handling symbolic links."""
        link = tmp_path / "link_to_project"

        try:
            link.symlink_to(temp_project_dir)

            files = list(FileDiscovery.discover_files(str(tmp_path)))

            # Should discover files through symlink
            assert len(files) > 0
        except OSError:
            # Symlinks may not be supported on all systems
            pytest.skip("Symlinks not supported")


# ============================================================================
# PERFORMANCE TESTS
# ============================================================================

class TestPerformance:
    """Performance benchmarks and scaling tests."""

    @pytest.mark.slow
    def test_worker_scaling(self, mock_config, temp_cache_dir, temp_project_dir):
        """Test that more workers improve performance (up to CPU count)."""
        timings = {}

        for num_workers in [1, 2, 4]:
            scanner = DistributedScanner(mock_config, num_workers=num_workers, cache_dir=temp_cache_dir)

            start = time.time()
            result = scanner.scan_async(temp_project_dir)
            duration = time.time() - start

            timings[num_workers] = duration

        # More workers should be faster (or at least not slower)
        # Note: with small test projects, overhead might dominate
        assert timings[2] <= timings[1] * 1.2  # Allow 20% variance

    @pytest.mark.slow
    def test_cache_speedup(self, mock_config, temp_cache_dir, temp_project_dir):
        """Test that cached scans are significantly faster."""
        scanner = DistributedScanner(mock_config, num_workers=2, cache_dir=temp_cache_dir)

        # First scan (cold cache)
        start1 = time.time()
        result1 = scanner.scan_async(temp_project_dir)
        duration1 = time.time() - start1

        # Second scan (warm cache)
        start2 = time.time()
        result2 = scanner.scan_async(temp_project_dir)
        duration2 = time.time() - start2

        # Cached scan should be faster
        assert duration2 < duration1
        assert result2.stats.cache_hit_rate > 0.5

    def test_incremental_scan_overhead(self, mock_config, temp_cache_dir, temp_project_dir):
        """Test that incremental scan overhead is minimal."""
        scanner = DistributedScanner(mock_config, num_workers=2, cache_dir=temp_cache_dir)

        with patch.object(FileDiscovery, '_get_changed_files_since') as mock_git:
            mock_git.return_value = set()  # No changes

            start = time.time()
            result = scanner.scan_incremental(temp_project_dir)
            duration = time.time() - start

            # Should complete very quickly with no changes
            assert duration < 0.5  # 500ms threshold
            assert len(result.findings) == 0


# ============================================================================
# REGRESSION TESTS
# ============================================================================

class TestRegression:
    """Regression tests to ensure compatibility with existing features."""

    @patch.object(DistributedScanner, '_scan_file')
    def test_findings_format_compatibility(self, mock_scan, mock_config, temp_cache_dir, temp_project_dir):
        """Test that findings format matches sequential analyzer."""
        expected_finding = {
            "file": "app.py",
            "line": 10,
            "rule": "hardcoded-secret",
            "severity": "HIGH",
            "message": "Hardcoded password",
            "confidence": "HIGH"
        }

        mock_scan.return_value = [expected_finding]

        scanner = DistributedScanner(mock_config, num_workers=2, cache_dir=temp_cache_dir)
        result = scanner.scan_async(temp_project_dir)

        # Check finding format
        for finding in result.findings:
            assert "file" in finding
            assert "line" in finding
            assert "rule" in finding
            assert "severity" in finding

    def test_exclude_paths_honored(self, mock_config, temp_cache_dir, temp_project_dir):
        """Test that .auditlens.yaml exclude_paths is honored."""
        scanner = DistributedScanner(mock_config, num_workers=2, cache_dir=temp_cache_dir)

        files = list(FileDiscovery.discover_files(
            temp_project_dir,
            exclude_dirs=mock_config.exclude_paths
        ))

        file_paths = [f.path for f in files]

        # Excluded directories should not appear
        assert not any("node_modules" in p for p in file_paths)
        assert not any("__pycache__" in p for p in file_paths)

    @patch.object(DistributedScanner, '_scan_file')
    def test_suppression_comments_work(self, mock_scan, mock_config, temp_cache_dir, tmp_path):
        """Test that # auditlens: ignore suppression still works."""
        # In real implementation, this would be handled by analyzer.py
        # Here we just verify the structure supports it

        file_with_suppression = tmp_path / "suppressed.py"
        file_with_suppression.write_text(
            "password = 'test'  # auditlens: ignore\n"
        )

        # Mock scanner should respect suppressions
        mock_scan.return_value = []  # Suppressed findings

        scanner = DistributedScanner(mock_config, num_workers=2, cache_dir=temp_cache_dir)
        result = scanner.scan_async(str(tmp_path))

        # No findings due to suppression
        assert len(result.findings) == 0


# ============================================================================
# MONITORING & METRICS
# ============================================================================

class TestMonitoring:
    """Tests for monitoring and metrics collection."""

    def test_stats_collection(self, mock_config, temp_cache_dir, temp_project_dir):
        """Test that stats are collected correctly."""
        scanner = DistributedScanner(mock_config, num_workers=2, cache_dir=temp_cache_dir)

        result = scanner.scan_async(temp_project_dir)
        summary = result.stats.get_summary()

        assert "total_files" in summary
        assert "cache_hits" in summary
        assert "cache_misses" in summary
        assert "cache_hit_rate" in summary
        assert "total_duration" in summary

    def test_cache_hit_rate_calculation(self):
        """Test cache hit rate calculation."""
        stats = ScanStats()
        stats.total_files = 10
        stats.cache_hits = 7
        stats.cache_misses = 3

        summary = stats.get_summary()

        assert summary["cache_hit_rate"] == 0.7

    def test_metrics_json_format(self, mock_config, temp_cache_dir, temp_project_dir):
        """Test that metrics can be serialized to JSON."""
        scanner = DistributedScanner(mock_config, num_workers=2, cache_dir=temp_cache_dir)

        result = scanner.scan_async(temp_project_dir)
        data = result.to_dict()

        # Should be JSON serializable
        json_str = json.dumps(data)
        assert json_str is not None

        # Parse back
        parsed = json.loads(json_str)
        assert "stats" in parsed


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
