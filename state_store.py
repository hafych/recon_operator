"""SQLite persistence for scheduled tasks and scan job history."""

from __future__ import annotations

import os
import sqlite3
import threading
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS scheduled_tasks (
    task_id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    scan_type TEXT NOT NULL,
    interval_minutes REAL NOT NULL,
    ports TEXT,
    scripts TEXT,
    discovery TEXT,
    owner_id TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_jobs (
    job_id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    scan_type TEXT NOT NULL,
    ports TEXT,
    scripts TEXT,
    discovery TEXT,
    status TEXT NOT NULL,
    kind TEXT NOT NULL,
    owner_id TEXT,
    created_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    error TEXT,
    result_file TEXT,
    result_json TEXT,
    lease_owner TEXT,
    lease_until REAL
);

CREATE INDEX IF NOT EXISTS idx_scan_jobs_created ON scan_jobs(created_at);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_status ON scan_jobs(status);

CREATE TABLE IF NOT EXISTS leadership (
    lock_name TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    lease_until REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    action TEXT NOT NULL,
    actor_key_id TEXT,
    actor_owner_prefix TEXT,
    target TEXT,
    scan_type TEXT,
    job_id TEXT,
    task_id TEXT,
    result_file TEXT,
    status TEXT,
    detail TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_events_ts ON audit_events(ts);
CREATE INDEX IF NOT EXISTS idx_audit_events_action ON audit_events(action);
"""


class _ClosingConnection(sqlite3.Connection):
    """SQLite connection that closes after its transaction context exits."""

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            return super().__exit__(exc_type, exc_value, traceback)
        finally:
            self.close()


class StateStore:
    """Thread-safe SQLite store for durable operator state."""

    def __init__(self, path: str):
        self.path = str(path)
        self._lock = threading.Lock()
        self._memory_uri: Optional[str] = None
        self._memory_keeper: Optional[sqlite3.Connection] = None
        if self.path == ":memory:":
            self._memory_uri = f"file:recon_operator_{uuid.uuid4().hex}?mode=memory&cache=shared"
            self._memory_keeper = sqlite3.connect(
                self._memory_uri,
                uri=True,
                timeout=30,
                check_same_thread=False,
            )
            self._configure_connection(self._memory_keeper)
        else:
            parent = Path(self.path).parent
            parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            Path(self.path).touch(mode=0o600, exist_ok=True)
            os.chmod(self.path, 0o600)
        with self._connect() as conn:
            conn.executescript(SCHEMA)
            # Serialize schema inspection + DDL across documented multi-worker
            # startup. CREATE TABLE above is idempotent; migrations are not.
            conn.execute("BEGIN EXCLUSIVE")
            self._migrate(conn)
            # Full scan payloads live only in Fernet-encrypted result files.
            # Purge plaintext rows left by older releases.
            conn.execute("UPDATE scan_jobs SET result_json = NULL WHERE result_json IS NOT NULL")
            conn.commit()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            self._memory_uri or self.path,
            uri=self._memory_uri is not None,
            timeout=30,
            check_same_thread=False,
            factory=_ClosingConnection,
        )
        self._configure_connection(conn)
        return conn

    def _configure_connection(self, conn: sqlite3.Connection) -> None:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA secure_delete=ON")
        if self._memory_uri is not None:
            return
        for suffix in ("", "-wal", "-shm"):
            candidate = f"{self.path}{suffix}"
            if os.path.exists(candidate):
                os.chmod(candidate, 0o600)

    def close(self) -> None:
        """Release the keeper used by shared ``:memory:`` stores."""
        if self._memory_keeper is not None:
            self._memory_keeper.close()
            self._memory_keeper = None

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    @staticmethod
    def _table_columns(conn: sqlite3.Connection, table: str) -> List[str]:
        rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
        return [row["name"] for row in rows]

    def _migrate(self, conn: sqlite3.Connection) -> None:
        job_cols = self._table_columns(conn, "scan_jobs")
        if "owner_id" not in job_cols:
            conn.execute("ALTER TABLE scan_jobs ADD COLUMN owner_id TEXT")
        if "lease_owner" not in job_cols:
            conn.execute("ALTER TABLE scan_jobs ADD COLUMN lease_owner TEXT")
        if "lease_until" not in job_cols:
            conn.execute("ALTER TABLE scan_jobs ADD COLUMN lease_until REAL")
        task_cols = self._table_columns(conn, "scheduled_tasks")
        if "owner_id" not in task_cols:
            conn.execute("ALTER TABLE scheduled_tasks ADD COLUMN owner_id TEXT")
        # Owner indexes after column migration so older DBs upgrade cleanly.
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_jobs_owner ON scan_jobs(owner_id)")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_scheduled_tasks_owner ON scheduled_tasks(owner_id)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_scan_jobs_lease ON scan_jobs(status, lease_until)"
        )

    def upsert_scheduled_task(
        self,
        task_id: str,
        target: str,
        scan_type: str,
        interval_minutes: float,
        *,
        ports: Optional[str] = None,
        scripts: Optional[str] = None,
        discovery: Optional[str] = None,
        owner_id: Optional[str] = None,
        created_at: str,
    ) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO scheduled_tasks(
                    task_id, target, scan_type, interval_minutes, ports, scripts,
                    discovery, owner_id, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(task_id) DO UPDATE SET
                    target=excluded.target,
                    scan_type=excluded.scan_type,
                    interval_minutes=excluded.interval_minutes,
                    ports=excluded.ports,
                    scripts=excluded.scripts,
                    discovery=excluded.discovery,
                    owner_id=excluded.owner_id
                """,
                (
                    task_id,
                    target,
                    scan_type,
                    float(interval_minutes),
                    ports,
                    scripts,
                    discovery,
                    owner_id,
                    created_at,
                ),
            )
            conn.commit()

    def delete_scheduled_task(self, task_id: str) -> bool:
        with self._lock, self._connect() as conn:
            cursor = conn.execute("DELETE FROM scheduled_tasks WHERE task_id = ?", (task_id,))
            conn.commit()
            return cursor.rowcount > 0

    def list_scheduled_tasks(self, owner_id: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            if owner_id:
                rows = conn.execute(
                    """
                    SELECT * FROM scheduled_tasks
                    WHERE owner_id IS NULL OR owner_id = ?
                    ORDER BY created_at ASC
                    """,
                    (owner_id,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM scheduled_tasks ORDER BY created_at ASC"
                ).fetchall()
        return [dict(row) for row in rows]

    def upsert_job(self, job: Dict[str, Any]) -> None:
        """Compatibility full-row upsert without persisting plaintext results.

        Runtime state-machine transitions should use the conditional helpers
        below. This method remains for fixtures/imported legacy state.
        """
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO scan_jobs(
                    job_id, target, scan_type, ports, scripts, discovery, status, kind,
                    owner_id, created_at, started_at, finished_at, error, result_file, result_json,
                    lease_owner, lease_until
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(job_id) DO UPDATE SET
                    target=excluded.target,
                    scan_type=excluded.scan_type,
                    ports=excluded.ports,
                    scripts=excluded.scripts,
                    discovery=excluded.discovery,
                    status=excluded.status,
                    kind=excluded.kind,
                    owner_id=excluded.owner_id,
                    started_at=excluded.started_at,
                    finished_at=excluded.finished_at,
                    error=excluded.error,
                    result_file=excluded.result_file,
                    result_json=NULL,
                    lease_owner=excluded.lease_owner,
                    lease_until=excluded.lease_until
                """,
                (
                    job["job_id"],
                    job.get("target") or "",
                    job.get("scan_type") or "",
                    job.get("ports"),
                    job.get("scripts"),
                    job.get("discovery"),
                    job.get("status") or "queued",
                    job.get("kind") or "immediate",
                    job.get("owner_id"),
                    job.get("created_at") or "",
                    job.get("started_at"),
                    job.get("finished_at"),
                    job.get("error"),
                    job.get("result_file"),
                    None,
                    job.get("lease_owner"),
                    job.get("lease_until"),
                ),
            )
            conn.commit()

    def insert_job(self, job: Dict[str, Any]) -> None:
        """Insert a newly queued job; fail if durable acceptance is impossible."""
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO scan_jobs(
                    job_id, target, scan_type, ports, scripts, discovery, status, kind,
                    owner_id, created_at, started_at, finished_at, error, result_file,
                    result_json, lease_owner, lease_until
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)
                """,
                (
                    job["job_id"],
                    job.get("target") or "",
                    job.get("scan_type") or "",
                    job.get("ports"),
                    job.get("scripts"),
                    job.get("discovery"),
                    job.get("status") or "queued",
                    job.get("kind") or "immediate",
                    job.get("owner_id"),
                    job.get("created_at") or "",
                    job.get("started_at"),
                    job.get("finished_at"),
                    job.get("error"),
                    job.get("result_file"),
                    job.get("lease_owner"),
                    job.get("lease_until"),
                ),
            )
            conn.commit()

    def insert_job_with_capacity(
        self,
        job: Dict[str, Any],
        *,
        max_active: int,
        dedupe_active: bool = False,
    ) -> tuple[Optional[Dict[str, Any]], bool]:
        """Atomically enforce global capacity and optionally reuse an active match.

        Returns ``(job, inserted)``. ``job`` is ``None`` when capacity is full.
        """
        with self._lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            if dedupe_active:
                existing = conn.execute(
                    """
                    SELECT * FROM scan_jobs
                    WHERE status IN ('queued', 'running')
                      AND kind = ?
                      AND owner_id IS ?
                      AND target = ?
                      AND scan_type = ?
                      AND ports IS ?
                      AND scripts IS ?
                      AND discovery IS ?
                    ORDER BY created_at ASC
                    LIMIT 1
                    """,
                    (
                        job.get("kind") or "immediate",
                        job.get("owner_id"),
                        job.get("target") or "",
                        job.get("scan_type") or "",
                        job.get("ports"),
                        job.get("scripts"),
                        job.get("discovery"),
                    ),
                ).fetchone()
                if existing is not None:
                    conn.commit()
                    return self._row_to_job(dict(existing)), False

            active_count = conn.execute(
                """
                SELECT COUNT(*) AS c
                FROM scan_jobs
                WHERE status IN ('queued', 'running')
                """
            ).fetchone()["c"]
            if active_count >= max(1, int(max_active)):
                conn.commit()
                return None, False

            conn.execute(
                """
                INSERT INTO scan_jobs(
                    job_id, target, scan_type, ports, scripts, discovery, status, kind,
                    owner_id, created_at, started_at, finished_at, error, result_file,
                    result_json, lease_owner, lease_until
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)
                """,
                (
                    job["job_id"],
                    job.get("target") or "",
                    job.get("scan_type") or "",
                    job.get("ports"),
                    job.get("scripts"),
                    job.get("discovery"),
                    job.get("status") or "queued",
                    job.get("kind") or "immediate",
                    job.get("owner_id"),
                    job.get("created_at") or "",
                    job.get("started_at"),
                    job.get("finished_at"),
                    job.get("error"),
                    job.get("result_file"),
                    job.get("lease_owner"),
                    job.get("lease_until"),
                ),
            )
            inserted = conn.execute(
                "SELECT * FROM scan_jobs WHERE job_id = ?",
                (job["job_id"],),
            ).fetchone()
            conn.commit()
        return self._row_to_job(dict(inserted)) if inserted is not None else None, True

    def mark_job_running(
        self,
        job_id: str,
        worker_id: str,
        *,
        started_at: str,
    ) -> Optional[Dict[str, Any]]:
        """Move a job from leased/queued to running under the same lease."""
        with self._lock, self._connect() as conn:
            cursor = conn.execute(
                """
                UPDATE scan_jobs
                SET status = 'running',
                    started_at = COALESCE(started_at, ?),
                    error = NULL
                WHERE job_id = ?
                  AND status IN ('queued', 'running')
                  AND lease_owner = ?
                """,
                (started_at, job_id, worker_id),
            )
            conn.commit()
            if cursor.rowcount < 1:
                return None
            row = conn.execute("SELECT * FROM scan_jobs WHERE job_id = ?", (job_id,)).fetchone()
        return self._row_to_job(dict(row)) if row is not None else None

    def finalize_job(
        self,
        job_id: str,
        worker_id: str,
        *,
        status: str,
        finished_at: str,
        error: Optional[str],
        result_file: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Atomically commit a terminal state while the caller still owns the job."""
        if status not in {"completed", "failed", "cancelled", "timeout"}:
            raise ValueError(f"Invalid terminal job status: {status}")
        with self._lock, self._connect() as conn:
            cursor = conn.execute(
                """
                UPDATE scan_jobs
                SET status = ?,
                    finished_at = ?,
                    error = ?,
                    result_file = ?,
                    result_json = NULL,
                    lease_owner = NULL,
                    lease_until = NULL
                WHERE job_id = ?
                  AND status = 'running'
                  AND lease_owner = ?
                """,
                (status, finished_at, error, result_file, job_id, worker_id),
            )
            conn.commit()
            if cursor.rowcount < 1:
                return None
            row = conn.execute("SELECT * FROM scan_jobs WHERE job_id = ?", (job_id,)).fetchone()
        return self._row_to_job(dict(row)) if row is not None else None

    def cancel_job_if_active(
        self,
        job_id: str,
        owner_id: str,
        *,
        finished_at: str,
        error: str,
    ) -> tuple[Optional[Dict[str, Any]], bool]:
        """Cancel an owned queued/running job without overwriting terminal state."""
        with self._lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            cursor = conn.execute(
                """
                UPDATE scan_jobs
                SET status = 'cancelled',
                    finished_at = ?,
                    error = ?,
                    result_json = NULL,
                    lease_owner = NULL,
                    lease_until = NULL
                WHERE job_id = ?
                  AND (owner_id IS NULL OR owner_id = ?)
                  AND status IN ('queued', 'running')
                """,
                (finished_at, error, job_id, owner_id),
            )
            row = conn.execute(
                """
                SELECT * FROM scan_jobs
                WHERE job_id = ? AND (owner_id IS NULL OR owner_id = ?)
                """,
                (job_id, owner_id),
            ).fetchone()
            conn.commit()
        return (
            self._row_to_job(dict(row)) if row is not None else None,
            cursor.rowcount > 0,
        )

    def requeue_owned_job(self, job_id: str, worker_id: str) -> bool:
        """Release a claimed-but-not-started job back to the durable queue."""
        with self._lock, self._connect() as conn:
            cursor = conn.execute(
                """
                UPDATE scan_jobs
                SET status = 'queued',
                    started_at = NULL,
                    error = NULL,
                    lease_owner = NULL,
                    lease_until = NULL
                WHERE job_id = ?
                  AND status = 'queued'
                  AND lease_owner = ?
                """,
                (job_id, worker_id),
            )
            conn.commit()
            return cursor.rowcount > 0

    def get_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT * FROM scan_jobs WHERE job_id = ?", (job_id,)).fetchone()
        if row is None:
            return None
        return self._row_to_job(dict(row))

    def list_jobs(self, limit: int = 200, owner_id: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            if owner_id:
                rows = conn.execute(
                    """
                    SELECT * FROM scan_jobs
                    WHERE owner_id IS NULL OR owner_id = ?
                    ORDER BY created_at DESC
                    LIMIT ?
                    """,
                    (owner_id, max(1, int(limit))),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM scan_jobs ORDER BY created_at DESC LIMIT ?",
                    (max(1, int(limit)),),
                ).fetchall()
        return [self._row_to_job(dict(row)) for row in rows]

    def prune_jobs(self, max_jobs: int) -> int:
        if max_jobs < 1:
            return 0
        with self._lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            count = conn.execute("SELECT COUNT(*) AS c FROM scan_jobs").fetchone()["c"]
            overflow = count - max_jobs
            if overflow <= 0:
                return 0
            cursor = conn.execute(
                """
                DELETE FROM scan_jobs WHERE job_id IN (
                    SELECT job_id FROM scan_jobs
                    WHERE status IN ('completed', 'failed', 'cancelled', 'timeout')
                    ORDER BY COALESCE(finished_at, created_at) ASC
                    LIMIT ?
                )
                """,
                (overflow,),
            )
            conn.commit()
            return max(0, cursor.rowcount)

    def delete_job(self, job_id: str) -> None:
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM scan_jobs WHERE job_id = ?", (job_id,))
            conn.commit()

    def try_claim_job(
        self,
        job_id: str,
        worker_id: str,
        *,
        now: float,
        lease_seconds: float,
        started_at: str,
    ) -> Optional[Dict[str, Any]]:
        """Atomically lease a queued (or expired-running) job for ``worker_id``."""
        lease_until = float(now) + float(lease_seconds)
        with self._lock, self._connect() as conn:
            cursor = conn.execute(
                """
                UPDATE scan_jobs
                SET status = 'queued',
                    lease_owner = ?,
                    lease_until = ?,
                    started_at = NULL,
                    error = NULL
                WHERE job_id = ?
                  AND (
                    (
                        status = 'queued'
                        AND (
                            lease_owner IS NULL
                            OR lease_owner = ?
                            OR lease_until IS NULL
                            OR lease_until < ?
                        )
                    )
                    OR (
                        status = 'running'
                        AND (lease_until IS NULL OR lease_until < ?)
                    )
                  )
                """,
                (worker_id, lease_until, job_id, worker_id, float(now), float(now)),
            )
            conn.commit()
            if cursor.rowcount < 1:
                return None
            row = conn.execute("SELECT * FROM scan_jobs WHERE job_id = ?", (job_id,)).fetchone()
        return self._row_to_job(dict(row)) if row is not None else None

    def claim_next_job(
        self,
        worker_id: str,
        *,
        now: float,
        lease_seconds: float,
        started_at: str,
    ) -> Optional[Dict[str, Any]]:
        """Claim the oldest claimable job in one cross-process transaction."""
        lease_until = float(now) + float(lease_seconds)
        with self._lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                """
                SELECT job_id FROM scan_jobs
                WHERE (
                        status = 'queued'
                        AND (lease_owner IS NULL OR lease_until IS NULL OR lease_until < ?)
                      )
                   OR (
                        status = 'running'
                        AND (lease_until IS NULL OR lease_until < ?)
                   )
                ORDER BY created_at ASC
                LIMIT 1
                """,
                (float(now), float(now)),
            ).fetchone()
            if row is None:
                conn.commit()
                return None
            job_id = row["job_id"]
            cursor = conn.execute(
                """
                UPDATE scan_jobs
                SET status = 'queued',
                    lease_owner = ?,
                    lease_until = ?,
                    started_at = NULL,
                    error = NULL
                WHERE job_id = ?
                  AND (
                    (
                        status = 'queued'
                        AND (lease_owner IS NULL OR lease_until IS NULL OR lease_until < ?)
                    )
                    OR (
                        status = 'running'
                        AND (lease_until IS NULL OR lease_until < ?)
                    )
                  )
                """,
                (worker_id, lease_until, job_id, float(now), float(now)),
            )
            if cursor.rowcount < 1:
                conn.commit()
                return None
            claimed = conn.execute(
                "SELECT * FROM scan_jobs WHERE job_id = ?",
                (job_id,),
            ).fetchone()
            conn.commit()
        return self._row_to_job(dict(claimed)) if claimed is not None else None

    def renew_job_lease(
        self,
        job_id: str,
        worker_id: str,
        *,
        now: float,
        lease_seconds: float,
    ) -> bool:
        lease_until = float(now) + float(lease_seconds)
        with self._lock, self._connect() as conn:
            cursor = conn.execute(
                """
                UPDATE scan_jobs
                SET lease_until = ?
                WHERE job_id = ?
                  AND lease_owner = ?
                  AND status IN ('queued', 'running')
                """,
                (lease_until, job_id, worker_id),
            )
            conn.commit()
            return cursor.rowcount > 0

    def release_job_lease(self, job_id: str, worker_id: str) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                UPDATE scan_jobs
                SET lease_owner = NULL, lease_until = NULL
                WHERE job_id = ? AND lease_owner = ?
                """,
                (job_id, worker_id),
            )
            conn.commit()

    def try_acquire_leadership(
        self,
        lock_name: str,
        worker_id: str,
        *,
        now: float,
        lease_seconds: float,
    ) -> bool:
        """Acquire or renew a named leadership lease (e.g. scheduler)."""
        lease_until = float(now) + float(lease_seconds)
        with self._lock, self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO leadership(lock_name, owner_id, lease_until)
                VALUES (?, ?, ?)
                ON CONFLICT(lock_name) DO UPDATE SET
                    owner_id = excluded.owner_id,
                    lease_until = excluded.lease_until
                WHERE leadership.lease_until < ?
                   OR leadership.owner_id = ?
                """,
                (lock_name, worker_id, lease_until, float(now), worker_id),
            )
            conn.commit()
            if cursor.rowcount > 0:
                return True
            row = conn.execute(
                "SELECT owner_id FROM leadership WHERE lock_name = ?",
                (lock_name,),
            ).fetchone()
            return bool(row and row["owner_id"] == worker_id)

    def get_leader(self, lock_name: str) -> Optional[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT lock_name, owner_id, lease_until FROM leadership WHERE lock_name = ?",
                (lock_name,),
            ).fetchone()
        return dict(row) if row is not None else None

    def release_leadership(self, lock_name: str, worker_id: str) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "DELETE FROM leadership WHERE lock_name = ? AND owner_id = ?",
                (lock_name, worker_id),
            )
            conn.commit()

    def append_audit_event(
        self,
        *,
        ts: str,
        action: str,
        actor_key_id: Optional[str] = None,
        actor_owner_prefix: Optional[str] = None,
        target: Optional[str] = None,
        scan_type: Optional[str] = None,
        job_id: Optional[str] = None,
        task_id: Optional[str] = None,
        result_file: Optional[str] = None,
        status: Optional[str] = None,
        detail: Optional[str] = None,
        max_events: int = 10_000,
    ) -> None:
        """Append an audit event and prune oldest rows beyond max_events."""
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO audit_events(
                    ts, action, actor_key_id, actor_owner_prefix, target, scan_type,
                    job_id, task_id, result_file, status, detail
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ts,
                    action,
                    actor_key_id,
                    actor_owner_prefix,
                    target,
                    scan_type,
                    job_id,
                    task_id,
                    result_file,
                    status,
                    detail,
                ),
            )
            if max_events > 0:
                conn.execute(
                    """
                    DELETE FROM audit_events
                    WHERE id NOT IN (
                        SELECT id FROM audit_events ORDER BY id DESC LIMIT ?
                    )
                    """,
                    (int(max_events),),
                )
            conn.commit()

    def list_audit_events(
        self,
        *,
        limit: int = 100,
        action: Optional[str] = None,
        actor_key_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        limit = max(1, min(int(limit), 1000))
        params: List[Any] = []
        if action and actor_key_id:
            query = """
                SELECT id, ts, action, actor_key_id, actor_owner_prefix, target, scan_type,
                       job_id, task_id, result_file, status, detail
                FROM audit_events
                WHERE action = ? AND actor_key_id = ?
                ORDER BY id DESC
                LIMIT ?
            """
            params.extend((action, actor_key_id))
        elif action:
            query = """
                SELECT id, ts, action, actor_key_id, actor_owner_prefix, target, scan_type,
                       job_id, task_id, result_file, status, detail
                FROM audit_events
                WHERE action = ?
                ORDER BY id DESC
                LIMIT ?
            """
            params.append(action)
        elif actor_key_id:
            query = """
                SELECT id, ts, action, actor_key_id, actor_owner_prefix, target, scan_type,
                       job_id, task_id, result_file, status, detail
                FROM audit_events
                WHERE actor_key_id = ?
                ORDER BY id DESC
                LIMIT ?
            """
            params.append(actor_key_id)
        else:
            query = """
                SELECT id, ts, action, actor_key_id, actor_owner_prefix, target, scan_type,
                       job_id, task_id, result_file, status, detail
                FROM audit_events
                ORDER BY id DESC
                LIMIT ?
            """
        params.append(limit)
        with self._lock, self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    @staticmethod
    def _row_to_job(row: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "job_id": row["job_id"],
            "target": row["target"],
            "scan_type": row["scan_type"],
            "ports": row.get("ports"),
            "scripts": row.get("scripts"),
            "discovery": row.get("discovery"),
            "status": row["status"],
            "kind": row.get("kind") or "immediate",
            "owner_id": row.get("owner_id"),
            "created_at": row.get("created_at"),
            "started_at": row.get("started_at"),
            "finished_at": row.get("finished_at"),
            "error": row.get("error"),
            "result_file": row.get("result_file"),
            "result": None,
            "lease_owner": row.get("lease_owner"),
            "lease_until": row.get("lease_until"),
            "task": None,
        }
