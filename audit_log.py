
import sqlite3
import json
from datetime import datetime, timezone

DATABASE_NAME = "ascsentinel.db"


def get_connection():
    connection = sqlite3.connect(DATABASE_NAME, timeout=10)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    with get_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                action_description TEXT NOT NULL,
                risk_score INTEGER,
                decision TEXT NOT NULL,
                reasons TEXT NOT NULL,
                analysis_json TEXT NOT NULL
            )
        """)

        # Add review fields to existing databases without deleting records.
        existing_columns = {
            row["name"]
            for row in connection.execute(
                "PRAGMA table_info(audit_logs)"
            ).fetchall()
        }

        migrations = {
            "review_status": (
                "ALTER TABLE audit_logs ADD COLUMN "
                "review_status TEXT NOT NULL DEFAULT 'NOT_REQUIRED'"
            ),
            "reviewer": (
                "ALTER TABLE audit_logs ADD COLUMN reviewer TEXT"
            ),
            "review_outcome": (
                "ALTER TABLE audit_logs ADD COLUMN review_outcome TEXT"
            ),
            "review_reason": (
                "ALTER TABLE audit_logs ADD COLUMN review_reason TEXT"
            ),
            "reviewed_at": (
                "ALTER TABLE audit_logs ADD COLUMN reviewed_at TEXT"
            ),
        }

        for column, sql in migrations.items():
            if column not in existing_columns:
                connection.execute(sql)

        # Existing APPROVAL decisions become pending review items.
        connection.execute("""
            UPDATE audit_logs
            SET review_status = 'PENDING'
            WHERE decision = 'APPROVAL'
              AND review_status = 'NOT_REQUIRED'
        """)


def log_decision(description, analysis, decision):
    timestamp = datetime.now(timezone.utc).isoformat()
    decision_name = str(decision.get("decision", "ERROR")).upper()

    review_status = (
        "PENDING" if decision_name == "APPROVAL"
        else "NOT_REQUIRED"
    )

    with get_connection() as connection:
        cursor = connection.execute("""
            INSERT INTO audit_logs (
                timestamp,
                action_description,
                risk_score,
                decision,
                reasons,
                analysis_json,
                review_status
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            timestamp,
            description,
            decision.get("risk_score"),
            decision_name,
            json.dumps(decision.get("reasons", [])),
            json.dumps(analysis),
            review_status,
        ))

        return cursor.lastrowid


def get_recent_logs(limit=100):
    limit = max(1, min(int(limit), 500))

    with get_connection() as connection:
        rows = connection.execute("""
            SELECT *
            FROM audit_logs
            ORDER BY id DESC
            LIMIT ?
        """, (limit,)).fetchall()

        return [dict(row) for row in rows]


def get_pending_reviews(limit=100):
    limit = max(1, min(int(limit), 500))

    with get_connection() as connection:
        rows = connection.execute("""
            SELECT *
            FROM audit_logs
            WHERE decision = 'APPROVAL'
              AND review_status = 'PENDING'
            ORDER BY id DESC
            LIMIT ?
        """, (limit,)).fetchall()

        return [dict(row) for row in rows]


def get_review_history(outcome=None, limit=100):
    limit = max(1, min(int(limit), 500))

    with get_connection() as connection:
        if outcome in ("APPROVED", "REJECTED"):
            rows = connection.execute("""
                SELECT *
                FROM audit_logs
                WHERE review_status = ?
                ORDER BY reviewed_at DESC, id DESC
                LIMIT ?
            """, (outcome, limit)).fetchall()
        else:
            rows = connection.execute("""
                SELECT *
                FROM audit_logs
                WHERE review_status IN ('APPROVED', 'REJECTED')
                ORDER BY reviewed_at DESC, id DESC
                LIMIT ?
            """, (limit,)).fetchall()

        return [dict(row) for row in rows]


def review_request(audit_id, reviewer, outcome, reason):
    outcome = str(outcome).upper()
    reviewer = str(reviewer).strip()
    reason = str(reason).strip()

    if outcome not in ("APPROVED", "REJECTED"):
        return {
            "success": False,
            "error": "Outcome must be APPROVED or REJECTED."
        }

    if not reviewer or not reason:
        return {
            "success": False,
            "error": "Reviewer and review reason are required."
        }

    reviewed_at = datetime.now(timezone.utc).isoformat()

    with get_connection() as connection:
        cursor = connection.execute("""
            UPDATE audit_logs
            SET review_status = ?,
                reviewer = ?,
                review_outcome = ?,
                review_reason = ?,
                reviewed_at = ?
            WHERE id = ?
              AND decision = 'APPROVAL'
              AND review_status = 'PENDING'
        """, (
            outcome,
            reviewer,
            outcome,
            reason,
            reviewed_at,
            audit_id,
        ))

        if cursor.rowcount != 1:
            return {
                "success": False,
                "error": (
                    "Request not found, not pending, "
                    "or already reviewed."
                )
            }

    return {
        "success": True,
        "audit_id": audit_id,
        "review_status": outcome,
        "reviewer": reviewer,
        "review_reason": reason,
        "reviewed_at": reviewed_at,
        "simulation": True,
    }


if __name__ == "__main__":
    initialize_database()
    print("AscSentinel audit database initialized.")



def clear_all_logs():
    """Delete all audit records, including review history."""
    with get_connection() as conn:
        cursor = conn.execute("DELETE FROM audit_logs")
        deleted_count = cursor.rowcount
        conn.commit()

    return deleted_count
