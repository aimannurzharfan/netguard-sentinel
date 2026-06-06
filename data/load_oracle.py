"""Load CVE knowledge and vector embeddings into the local Oracle 23ai instance.

Run after fetch_cache.py:
    python -m data.load_oracle

Prerequisites: Oracle 23ai container running, ORACLE_USER/PASSWORD/DSN in .env.

Table cve_knowledge is created in the USERS tablespace (VECTOR columns require
automatic segment space management; the SYSTEM tablespace throws ORA-43853).
"""

from __future__ import annotations

import array
import json
import os
from pathlib import Path

import oracledb
from dotenv import load_dotenv

from data.embed import embed_batch

load_dotenv()

CACHE_FILE = Path(__file__).parent / "cache" / "cves.json"

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS cve_knowledge (
    id          VARCHAR2(20)    PRIMARY KEY,
    service_tag VARCHAR2(200),
    cvss        NUMBER(3,1),
    epss        NUMBER(6,5),
    kev         NUMBER(1)       DEFAULT 0,
    description VARCHAR2(4000),
    embedding   VECTOR(384, FLOAT32)
) TABLESPACE USERS
"""

UPSERT_SQL = """
MERGE INTO cve_knowledge tgt
USING (SELECT :id AS id FROM dual) src
ON (tgt.id = src.id)
WHEN MATCHED THEN UPDATE SET
    service_tag = :service_tag, cvss = :cvss, epss = :epss,
    kev = :kev, description = :description, embedding = :embedding
WHEN NOT MATCHED THEN INSERT
    (id, service_tag, cvss, epss, kev, description, embedding)
    VALUES (:id, :service_tag, :cvss, :epss, :kev, :description, :embedding)
"""


def _connect() -> oracledb.Connection:
    return oracledb.connect(
        user=os.environ["ORACLE_USER"],
        password=os.environ["ORACLE_PASSWORD"],
        dsn=os.environ.get("ORACLE_DSN", "localhost:1521/FREEPDB1"),
    )


def _to_vector(floats: list[float]) -> array.array:
    return array.array("f", floats)


def load() -> None:
    if not CACHE_FILE.exists():
        raise FileNotFoundError(f"Cache not found: {CACHE_FILE}. Run data/fetch_cache.py first.")

    records = json.loads(CACHE_FILE.read_text())
    print(f"Loaded {len(records)} records from cache.")

    texts = [r["description"] for r in records]
    print("Generating embeddings...")
    embeddings = embed_batch(texts)

    con = _connect()
    cur = con.cursor()

    cur.execute(CREATE_TABLE_SQL)
    con.commit()

    print("Inserting into Oracle...")
    for rec, emb in zip(records, embeddings):
        cur.execute(
            UPSERT_SQL,
            {
                "id": rec["id"],
                "service_tag": rec["service_tag"],
                "cvss": rec["cvss"],
                "epss": rec["epss"],
                "kev": 1 if rec["kev"] else 0,
                "description": rec["description"][:4000],
                "embedding": _to_vector(emb),
            },
        )
    con.commit()
    cur.close()
    con.close()
    print(f"Loaded {len(records)} CVE records into cve_knowledge.")


if __name__ == "__main__":
    load()
