"""Oracle 23ai AI Vector Search backend for the threat_intel tool.

Embeds the service string, then queries cve_knowledge by cosine similarity
to retrieve the most relevant CVE records. Returns the same shape as the
cache backend so threat_intel.py is backend-agnostic.

Requires the cve_knowledge table to be populated (data/load_oracle.py).
"""

from __future__ import annotations

import array
import os

import oracledb
from dotenv import load_dotenv

from data.embed import embed

load_dotenv()

TOP_K = 10
SIMILARITY_THRESHOLD = 0.6  # cosine similarity; lower distance = more similar

SEARCH_SQL = """
SELECT id, service_tag, cvss, epss, kev, description,
       1 - VECTOR_DISTANCE(embedding, :1, COSINE) AS similarity
FROM cve_knowledge
ORDER BY VECTOR_DISTANCE(embedding, :1, COSINE)
FETCH FIRST :2 ROWS ONLY
"""


def _connect() -> oracledb.Connection:
    return oracledb.connect(
        user=os.environ["ORACLE_USER"],
        password=os.environ["ORACLE_PASSWORD"],
        dsn=os.environ.get("ORACLE_DSN", "localhost:1521/FREEPDB1"),
    )


def lookup(service: str, top_k: int = TOP_K) -> list[dict]:
    """Vector-search CVE records relevant to a service description.

    Returns list of dicts with keys: id, cvss, epss, kev, description, similarity.
    """
    vec = array.array("f", embed(service))
    con = _connect()
    cur = con.cursor()
    cur.execute(SEARCH_SQL, [vec, top_k])
    if cur.description is None:
        cur.close()
        con.close()
        return []
    cols = [d[0].lower() for d in cur.description]
    rows = cur.fetchall()
    cur.close()
    con.close()

    results = []
    for row in rows:
        rec = dict(zip(cols, row))
        if rec.get("similarity", 0) < SIMILARITY_THRESHOLD:
            continue
        results.append({
            "id": rec["id"],
            "cvss": float(rec["cvss"] or 0),
            "epss": float(rec["epss"] or 0),
            "kev": bool(rec["kev"]),
            "description": rec.get("description", ""),
            "similarity": float(rec.get("similarity", 0)),
        })
    return results
