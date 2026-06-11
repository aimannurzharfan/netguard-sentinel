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
from tools.threat_intel import product_key

load_dotenv()

CACHE_FILE = Path(__file__).parent / "cache" / "cves.json"

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS cve_knowledge (
    id          VARCHAR2(20)    PRIMARY KEY,
    service_tag VARCHAR2(200),
    product_key VARCHAR2(50),
    cvss        NUMBER(3,1),
    epss        NUMBER(6,5),
    kev         NUMBER(1)       DEFAULT 0,
    description VARCHAR2(4000),
    embedding   VECTOR(384, FLOAT32)
) TABLESPACE USERS
"""

# Pre-23ai tables lack the product_key column; ORA-01430 means it already exists.
ADD_PRODUCT_KEY_SQL = "ALTER TABLE cve_knowledge ADD (product_key VARCHAR2(50))"

UPSERT_SQL = """
MERGE INTO cve_knowledge tgt
USING (SELECT :id AS id FROM dual) src
ON (tgt.id = src.id)
WHEN MATCHED THEN UPDATE SET
    service_tag = :service_tag, product_key = :product_key,
    cvss = :cvss, epss = :epss,
    kev = :kev, description = :description, embedding = :embedding
WHEN NOT MATCHED THEN INSERT
    (id, service_tag, product_key, cvss, epss, kev, description, embedding)
    VALUES (:id, :service_tag, :product_key, :cvss, :epss, :kev,
            :description, :embedding)
"""


def _connect() -> oracledb.Connection:
    user = os.getenv("ORACLE_USER", "system")
    password = os.getenv("ORACLE_PASSWORD")
    if not password:
        raise RuntimeError(
            "ORACLE_PASSWORD is not set. Add it to your .env file:\n"
            "  ORACLE_PASSWORD=<password you set when starting the container>"
        )
    dsn = os.getenv("ORACLE_DSN", "localhost:1521/FREEPDB1")
    return oracledb.connect(user=user, password=password, dsn=dsn)


def _to_vector(floats: list[float]) -> array.array:
    return array.array("f", floats)


def load() -> None:
    if not CACHE_FILE.exists():
        raise FileNotFoundError(
            f"Cache not found: {CACHE_FILE}. Run data/fetch_cache.py first."
        )

    records = json.loads(CACHE_FILE.read_text())
    print(f"Loaded {len(records)} records from cache.")

    texts = [r["description"] for r in records]
    print("Generating embeddings...")
    embeddings = embed_batch(texts)

    con = _connect()
    cur = con.cursor()

    cur.execute(CREATE_TABLE_SQL)
    try:
        cur.execute(ADD_PRODUCT_KEY_SQL)
    except oracledb.DatabaseError as exc:
        (error,) = exc.args
        if error.code != 1430:  # column being added already exists
            raise
    con.commit()

    print("Inserting into Oracle...")
    for rec, emb in zip(records, embeddings):
        cur.execute(
            UPSERT_SQL,
            {
                "id": rec["id"],
                "service_tag": rec["service_tag"],
                "product_key": rec.get("product")
                or product_key(rec.get("service_tag", "")),
                "cvss": rec["cvss"],
                "epss": rec["epss"],
                "kev": 1 if rec["kev"] else 0,
                "description": rec["description"][:4000],
                "embedding": _to_vector(emb),
            },
        )
    con.commit()
    cur.execute("SELECT COUNT(*) FROM cve_knowledge")
    row = cur.fetchone()
    total = row[0] if row else 0
    cur.close()
    con.close()
    print(f"cve_knowledge now contains {total} row(s).")


if __name__ == "__main__":
    load()
