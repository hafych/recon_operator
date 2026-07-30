import os
import sqlite3
import tempfile
import unittest

from state_store import StateStore


class StateStoreTests(unittest.TestCase):
    def test_memory_store_survives_across_method_connections(self):
        store = StateStore(":memory:")
        try:
            store.insert_job(
                {
                    "job_id": "memory-job",
                    "target": "127.0.0.1",
                    "scan_type": "Ping",
                    "status": "queued",
                    "kind": "immediate",
                    "created_at": "t0",
                }
            )
            self.assertEqual(store.get_job("memory-job")["status"], "queued")
        finally:
            store.close()

    def test_connection_context_closes_after_transaction(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = StateStore(os.path.join(tmp, "connection.db"))
            conn = store._connect()
            with conn as active:
                self.assertEqual(active.execute("SELECT 1").fetchone()[0], 1)

            with self.assertRaises(sqlite3.ProgrammingError):
                conn.execute("SELECT 1")

    def test_scheduled_tasks_and_jobs_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = StateStore(os.path.join(tmp, "state.db"))
            store.upsert_scheduled_task(
                "oabcdef123456-127.0.0.1-TCP",
                "127.0.0.1",
                "TCP",
                15,
                ports="22,80",
                scripts=None,
                discovery="auto",
                owner_id="owner-a",
                created_at="2026-07-15T00:00:00+00:00",
            )
            tasks = store.list_scheduled_tasks(owner_id="owner-a")
            self.assertEqual(len(tasks), 1)
            self.assertEqual(tasks[0]["discovery"], "auto")
            self.assertEqual(tasks[0]["owner_id"], "owner-a")

            store.upsert_job(
                {
                    "job_id": "job-1",
                    "target": "127.0.0.1",
                    "scan_type": "Hybrid",
                    "ports": None,
                    "scripts": None,
                    "discovery": "naabu",
                    "owner_id": "owner-a",
                    "status": "completed",
                    "kind": "immediate",
                    "created_at": "t0",
                    "started_at": "t1",
                    "finished_at": "t2",
                    "error": None,
                    "result_file": "file.json",
                    "result": {"hosts": []},
                }
            )
            loaded = store.get_job("job-1")
            self.assertEqual(loaded["status"], "completed")
            self.assertIsNone(loaded["result"])
            with sqlite3.connect(store.path) as conn:
                persisted_result = conn.execute(
                    "SELECT result_json FROM scan_jobs WHERE job_id = 'job-1'"
                ).fetchone()[0]
            self.assertIsNone(persisted_result)
            self.assertEqual(os.stat(store.path).st_mode & 0o777, 0o600)
            self.assertEqual(loaded["owner_id"], "owner-a")
            self.assertEqual(store.list_jobs(owner_id="owner-a")[0]["job_id"], "job-1")
            self.assertEqual(store.list_jobs(owner_id="owner-b"), [])

            store.delete_scheduled_task("oabcdef123456-127.0.0.1-TCP")
            self.assertEqual(store.list_scheduled_tasks(), [])

            for index in range(5):
                store.upsert_job(
                    {
                        "job_id": f"j{index}",
                        "target": "t",
                        "scan_type": "Ping",
                        "status": "completed",
                        "kind": "immediate",
                        "created_at": f"t{index}",
                        "finished_at": f"t{index}",
                        "result": None,
                    }
                )
            deleted = store.prune_jobs(2)
            self.assertGreaterEqual(deleted, 3)
            self.assertLessEqual(len(store.list_jobs()), 2)

    def test_job_lease_claim_is_exclusive(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = StateStore(os.path.join(tmp, "lease.db"))
            store.upsert_job(
                {
                    "job_id": "lease-1",
                    "target": "127.0.0.1",
                    "scan_type": "Ping",
                    "status": "queued",
                    "kind": "immediate",
                    "created_at": "t0",
                    "result": None,
                }
            )
            now = 1_000_000.0
            first = store.try_claim_job(
                "lease-1",
                "worker-a",
                now=now,
                lease_seconds=30,
                started_at="t1",
            )
            self.assertIsNotNone(first)
            self.assertEqual(first["status"], "queued")
            self.assertEqual(first["lease_owner"], "worker-a")
            running = store.mark_job_running("lease-1", "worker-a", started_at="t1")
            self.assertIsNotNone(running)
            self.assertEqual(running["status"], "running")

            second = store.try_claim_job(
                "lease-1",
                "worker-b",
                now=now + 1,
                lease_seconds=30,
                started_at="t2",
            )
            self.assertIsNone(second)

            # Expired lease can be reclaimed by another worker.
            third = store.try_claim_job(
                "lease-1",
                "worker-b",
                now=now + 60,
                lease_seconds=30,
                started_at="t3",
            )
            self.assertIsNotNone(third)
            self.assertEqual(third["status"], "queued")
            self.assertEqual(third["lease_owner"], "worker-b")
            # Keep lease-1 active so claim_next must pick a different job.
            self.assertTrue(
                store.renew_job_lease("lease-1", "worker-b", now=now + 120, lease_seconds=300)
            )

            store.upsert_job(
                {
                    "job_id": "lease-2",
                    "target": "127.0.0.1",
                    "scan_type": "TCP",
                    "status": "queued",
                    "kind": "immediate",
                    "created_at": "t4",
                    "result": None,
                }
            )
            claimed = store.claim_next_job(
                "worker-c",
                now=now + 125,
                lease_seconds=30,
                started_at="t5",
            )
            self.assertIsNotNone(claimed)
            self.assertEqual(claimed["job_id"], "lease-2")
            self.assertTrue(
                store.renew_job_lease("lease-2", "worker-c", now=now + 130, lease_seconds=30)
            )
            store.release_job_lease("lease-2", "worker-c")
            released = store.get_job("lease-2")
            self.assertIsNone(released.get("lease_owner"))

    def test_terminal_updates_are_fenced_by_status_and_lease_owner(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = StateStore(os.path.join(tmp, "fence.db"))
            store.insert_job(
                {
                    "job_id": "job",
                    "target": "127.0.0.1",
                    "scan_type": "Ping",
                    "status": "queued",
                    "kind": "immediate",
                    "created_at": "t0",
                }
            )
            claimed = store.try_claim_job(
                "job",
                "worker-a",
                now=1,
                lease_seconds=30,
                started_at="t1",
            )
            self.assertIsNotNone(claimed)
            self.assertIsNotNone(store.mark_job_running("job", "worker-a", started_at="t1"))
            self.assertIsNone(
                store.finalize_job(
                    "job",
                    "worker-b",
                    status="completed",
                    finished_at="t2",
                    error=None,
                    result_file="wrong.json",
                )
            )
            cancelled, changed = store.cancel_job_if_active(
                "job",
                "owner-a",
                finished_at="t2",
                error="cancelled",
            )
            # An unowned legacy row is visible/cancellable, but completion can
            # no longer resurrect it after the terminal transition.
            self.assertTrue(changed)
            self.assertEqual(cancelled["status"], "cancelled")
            self.assertIsNone(
                store.finalize_job(
                    "job",
                    "worker-a",
                    status="completed",
                    finished_at="t3",
                    error=None,
                    result_file="late.json",
                )
            )
            self.assertEqual(store.get_job("job")["status"], "cancelled")

    def test_capacity_and_scheduled_deduplication_are_atomic(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = StateStore(os.path.join(tmp, "capacity.db"))
            first = {
                "job_id": "one",
                "target": "127.0.0.1",
                "scan_type": "Ping",
                "status": "queued",
                "kind": "scheduled",
                "owner_id": "owner",
                "created_at": "t0",
            }
            accepted, inserted = store.insert_job_with_capacity(
                first,
                max_active=1,
                dedupe_active=True,
            )
            self.assertTrue(inserted)
            self.assertEqual(accepted["job_id"], "one")

            duplicate, inserted_duplicate = store.insert_job_with_capacity(
                {**first, "job_id": "two", "created_at": "t1"},
                max_active=1,
                dedupe_active=True,
            )
            self.assertFalse(inserted_duplicate)
            self.assertEqual(duplicate["job_id"], "one")

            rejected, inserted_rejected = store.insert_job_with_capacity(
                {**first, "job_id": "three", "target": "127.0.0.2"},
                max_active=1,
                dedupe_active=True,
            )
            self.assertIsNone(rejected)
            self.assertFalse(inserted_rejected)

    def test_leadership_is_exclusive_until_expired(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = StateStore(os.path.join(tmp, "leader.db"))
            now = 2_000_000.0
            self.assertTrue(
                store.try_acquire_leadership("scheduler", "worker-a", now=now, lease_seconds=30)
            )
            self.assertFalse(
                store.try_acquire_leadership("scheduler", "worker-b", now=now + 1, lease_seconds=30)
            )
            # Owner can renew.
            self.assertTrue(
                store.try_acquire_leadership("scheduler", "worker-a", now=now + 5, lease_seconds=30)
            )
            # Expired lease is stealeable.
            self.assertTrue(
                store.try_acquire_leadership(
                    "scheduler", "worker-b", now=now + 40, lease_seconds=30
                )
            )
            leader = store.get_leader("scheduler")
            self.assertEqual(leader["owner_id"], "worker-b")
            store.release_leadership("scheduler", "worker-b")
            self.assertIsNone(store.get_leader("scheduler"))

    def test_audit_events_append_list_and_prune(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = StateStore(os.path.join(tmp, "audit.db"))
            for index in range(5):
                store.append_audit_event(
                    ts=f"t{index}",
                    action="scan.create" if index % 2 == 0 else "scan.finish",
                    actor_key_id="primary",
                    actor_owner_prefix="abcd12345678",
                    target="127.0.0.1",
                    scan_type="Ping",
                    job_id=f"job-{index}",
                    max_events=3,
                )
            events = store.list_audit_events(limit=10)
            self.assertEqual(len(events), 3)
            self.assertEqual(events[0]["job_id"], "job-4")
            only_create = store.list_audit_events(action="scan.create", limit=10)
            self.assertTrue(all(row["action"] == "scan.create" for row in only_create))
            by_actor = store.list_audit_events(actor_key_id="primary", limit=10)
            self.assertEqual(len(by_actor), 3)
            combined = store.list_audit_events(
                action="scan.create", actor_key_id="primary", limit=10
            )
            self.assertTrue(combined)
            self.assertTrue(
                all(
                    row["action"] == "scan.create" and row["actor_key_id"] == "primary"
                    for row in combined
                )
            )


if __name__ == "__main__":
    unittest.main()
