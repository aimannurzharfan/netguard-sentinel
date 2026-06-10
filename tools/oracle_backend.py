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
from tools.threat_intel import product_key

load_dotenv()

TOP_K = 10
SIMILARITY_THRESHOLD = 0.6  # cosine similarity; lower distance = more similar

# Named binds (not :1/:2): the embedding vector appears twice, and named binds
# let it be supplied once. Positional binds would count each :1 occurrence
# separately and raise DPY-4009 (3 placeholders, 2 values).
SEARCH_SQL = """
SELECT id, service_tag, cvss, epss, kev, description,
       1 - VECTOR_DISTANCE(embedding, :vec, COSINE) AS similarity
FROM cve_knowledge
ORDER BY VECTOR_DISTANCE(embedding, :vec, COSINE)
FETCH FIRST :top_k ROWS ONLY
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


def lookup(service: str, top_k: int = TOP_K) -> list[dict]:
    """Vector-search CVE records relevant to a service description.

    Returns list of dicts with keys: id, cvss, epss, kev, description, similarity.

    Vector similarity alone can surface CVEs for a different product that
    shares vendor words (e.g. Apache Struts for an Apache httpd query), so
    results are also gated on an exact product-key match.
    """
    svc_product = product_key(service)
    if not svc_product:
        return []
    vec = array.array("f", embed(service))
    con = _connect()
    cur = con.cursor()
    cur.execute(SEARCH_SQL, {"vec": vec, "top_k": top_k})
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
        if product_key(str(rec.get("service_tag") or "")) != svc_product:
            continue
        results.append(
            {
                "id": rec["id"],
                "cvss": float(rec["cvss"] or 0),
                "epss": float(rec["epss"] or 0),
                "kev": bool(rec["kev"]),
                "description": rec.get("description", ""),
                "similarity": float(rec.get("similarity", 0)),
            }
        )
    return results
