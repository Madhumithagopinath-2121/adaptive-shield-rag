"""SQLite persistence layer for document storage.

Provides parameterized SQL operations to ensure untrusted content is never
interpolated directly into database commands.
"""

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3
from typing import Any, Dict, Generator, List, Optional
import uuid

from app.config import settings
from app.models.document import Document, DocumentStatus


def resolve_db_path(db_path: Optional[str] = None) -> str:
    """Resolve database path, ensuring parent directories exist."""
    path_val = db_path if db_path is not None else settings.sqlite_db_path
    if path_val == ":memory:":
        return ":memory:"

    target = Path(path_val)
    if not target.is_absolute():
        # Backend directory is parent of app; project root is parent of backend
        backend_dir = Path(__file__).resolve().parent.parent
        project_root = backend_dir.parent
        target = (project_root / target).resolve()

    target.parent.mkdir(parents=True, exist_ok=True)
    return str(target)


@contextmanager
def get_db_connection(
    db_path: Optional[str] = None,
) -> Generator[sqlite3.Connection, None, None]:
    """Provide a transactional SQLite database connection context."""
    resolved = resolve_db_path(db_path)
    conn = sqlite3.connect(resolved)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(db_path: Optional[str] = None) -> None:
    """Initialize database tables and indexes."""
    with get_db_connection(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS documents (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                source TEXT NOT NULL,
                source_type TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                status TEXT NOT NULL
            );
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_documents_timestamp
            ON documents(timestamp DESC);
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_documents_status
            ON documents(status);
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS security_assessments (
                id TEXT PRIMARY KEY,
                document_id TEXT NOT NULL,
                risk_score REAL NOT NULL,
                decision TEXT NOT NULL,
                timestamp TEXT NOT NULL
            );
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_assessments_document_id
            ON security_assessments(document_id);
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_assessments_timestamp
            ON security_assessments(timestamp DESC);
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_assessments_decision
            ON security_assessments(decision);
            """
        )


def _row_to_document(row: sqlite3.Row) -> Document:
    """Convert an SQLite Row to a Document model instance."""
    return Document(
        id=row["id"],
        title=row["title"],
        content=row["content"],
        source=row["source"],
        source_type=row["source_type"],
        timestamp=datetime.fromisoformat(row["timestamp"]),
        status=DocumentStatus(row["status"]),
    )


def insert_document(doc: Document, db_path: Optional[str] = None) -> Document:
    """Insert a new document record using parameterized SQL."""
    with get_db_connection(db_path) as conn:
        conn.execute(
            """
            INSERT INTO documents (
                id, title, content, source, source_type, timestamp, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?);
            """,
            (
                doc.id,
                doc.title,
                doc.content,
                doc.source,
                doc.source_type,
                doc.timestamp.isoformat(),
                doc.status.value,
            ),
        )
    return doc


def get_document_by_id(
    document_id: str, db_path: Optional[str] = None
) -> Optional[Document]:
    """Retrieve a single document by unique identifier."""
    with get_db_connection(db_path) as conn:
        cursor = conn.execute(
            """
            SELECT id, title, content, source, source_type, timestamp, status
            FROM documents
            WHERE id = ?;
            """,
            (document_id,),
        )
        row = cursor.fetchone()
        if row is None:
            return None
        return _row_to_document(row)


def get_recent_documents(
    limit: int = 50, offset: int = 0, db_path: Optional[str] = None
) -> List[Document]:
    """Retrieve recent documents ordered by timestamp descending."""
    with get_db_connection(db_path) as conn:
        cursor = conn.execute(
            """
            SELECT id, title, content, source, source_type, timestamp, status
            FROM documents
            ORDER BY timestamp DESC
            LIMIT ? OFFSET ?;
            """,
            (limit, offset),
        )
        rows = cursor.fetchall()
        return [_row_to_document(r) for r in rows]


def update_document_status(
    document_id: str, status: DocumentStatus, db_path: Optional[str] = None
) -> Optional[Document]:
    """Update a document's status without altering content or metadata."""
    with get_db_connection(db_path) as conn:
        cursor = conn.execute(
            """
            UPDATE documents
            SET status = ?
            WHERE id = ?;
            """,
            (status.value, document_id),
        )
        if cursor.rowcount == 0:
            return None

    return get_document_by_id(document_id, db_path=db_path)


def record_security_assessment(
    document_id: str,
    risk_score: float,
    decision: str,
    timestamp: Optional[datetime] = None,
    assessment_id: Optional[str] = None,
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Record that a security assessment occurred.

    Does not modify documents.status or alter document records.
    """
    aid = assessment_id or str(uuid.uuid4())
    ts = timestamp or datetime.now(timezone.utc)
    ts_str = ts.isoformat()

    with get_db_connection(db_path) as conn:
        conn.execute(
            """
            INSERT INTO security_assessments (
                id, document_id, risk_score, decision, timestamp
            ) VALUES (?, ?, ?, ?, ?);
            """,
            (aid, document_id, risk_score, decision, ts_str),
        )

    return {
        "id": aid,
        "document_id": document_id,
        "risk_score": risk_score,
        "decision": decision,
        "timestamp": ts_str,
    }


def get_recent_assessments(
    window_seconds: Optional[int] = None,
    limit: int = 1000,
    db_path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Retrieve recent assessments within an optional rolling time window."""
    with get_db_connection(db_path) as conn:
        if window_seconds is not None:
            cutoff = (
                datetime.now(timezone.utc) - timedelta(seconds=window_seconds)
            ).isoformat()
            cursor = conn.execute(
                """
                SELECT id, document_id, risk_score, decision, timestamp
                FROM security_assessments
                WHERE timestamp >= ?
                ORDER BY timestamp DESC
                LIMIT ?;
                """,
                (cutoff, limit),
            )
        else:
            cursor = conn.execute(
                """
                SELECT id, document_id, risk_score, decision, timestamp
                FROM security_assessments
                ORDER BY timestamp DESC
                LIMIT ?;
                """,
                (limit,),
            )
        rows = cursor.fetchall()
        return [
            {
                "id": r["id"],
                "document_id": r["document_id"],
                "risk_score": float(r["risk_score"]),
                "decision": r["decision"],
                "timestamp": r["timestamp"],
            }
            for r in rows
        ]
