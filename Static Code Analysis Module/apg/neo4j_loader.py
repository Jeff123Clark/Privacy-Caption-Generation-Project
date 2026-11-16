"""Load an APG into Neo4j (5.x) over Bolt.

All nodes share the label ``:APG`` with a uniqueness constraint on ``uid``; the
specific label (``:Method``, ``:Statement`` ...) is added alongside. Loading an
app first deletes any previous graph with the same ``app_id`` so reruns are clean,
while other apps in the database are left untouched.
"""

from __future__ import annotations

from typing import Any, Iterable

from .graph import APG, NODE_LABELS

SCHEMA = [
    "CREATE CONSTRAINT apg_uid IF NOT EXISTS FOR (n:APG) REQUIRE n.uid IS UNIQUE",
    "CREATE INDEX apg_app IF NOT EXISTS FOR (n:APG) ON (n.app_id)",
    "CREATE INDEX method_sig IF NOT EXISTS FOR (n:Method) ON (n.signature)",
    "CREATE INDEX method_cls_name IF NOT EXISTS FOR (n:Method) ON (n.class_name, n.name)",
    "CREATE INDEX method_java_sig IF NOT EXISTS FOR (n:Method) ON (n.java_signature)",
    "CREATE INDEX stmt_target IF NOT EXISTS FOR (n:Statement) ON (n.target)",
    "CREATE INDEX stmt_kind IF NOT EXISTS FOR (n:Statement) ON (n.kind)",
    "CREATE INDEX field_cls_name IF NOT EXISTS FOR (n:Field) ON (n.class_name, n.name)",
    "CREATE INDEX class_name IF NOT EXISTS FOR (n:Class) ON (n.name)",
    "CREATE INDEX perm_name IF NOT EXISTS FOR (n:Permission) ON (n.name)",
    "CREATE INDEX stmt_cross IF NOT EXISTS FOR (n:Statement) ON (n.cross_batch)",
]

# Edges that several detail batches (or the overview) can all contain: merged, not duplicated.
SHARED_EDGES = {"HAS_CLASS", "HAS_METHOD", "HAS_FIELD", "USES_PERMISSION", "DECLARES_PERMISSION",
                "HAS_COMPONENT", "USES_LIBRARY", "BELONGS_TO", "GUARDED_BY", "IMPLEMENTED_BY",
                "API_REQUIRES_PERMISSION", "EXTENDS", "IMPLEMENTS", "OVERRIDES"}

# A stub (a method or class known only as a call target) or an overview node only fills in a
# node that no detail batch has described; entry points found by either level are kept.
_WEAK_NODE = """UNWIND $rows AS row MERGE (n:APG {uid: row.uid})
ON CREATE SET n:%s, n += row
ON MATCH SET n.is_entrypoint = coalesce(n.is_entrypoint, false) OR coalesce(row.is_entrypoint, false),
             n.entrypoint_kind = coalesce(n.entrypoint_kind, row.entrypoint_kind),
             n.in_apk = coalesce(row.in_apk, n.in_apk)
WITH n, row
// A detail batch only saw this method/class as a call target (a stub); the overview knows it
// is defined in the APK (e.g. SDK code), so its description replaces the stub's.
FOREACH (_ IN CASE WHEN row.level = 'overview' AND coalesce(n.is_external, false)
                         AND n.has_statements IS NULL AND n.level IS NULL THEN [1] ELSE [] END |
  SET n += row)"""
_STRONG_NODE = """UNWIND $rows AS row MERGE (n:APG {uid: row.uid})
WITH n, row, coalesce(n.is_entrypoint, false) AS ep, n.entrypoint_kind AS ek, n.in_apk AS ia
SET n:%s, n += row
SET n.is_entrypoint = coalesce(row.is_entrypoint, false) OR ep,
    n.entrypoint_kind = coalesce(row.entrypoint_kind, ek), n.in_apk = coalesce(ia, row.in_apk)"""

# Join detail batches: calls marked cross_batch reach a method built in another batch.
STITCH = [
    ("CALL_FLOW", """MATCH (c:Statement {cross_batch: true}) WHERE c.app_id = $app
CALL (c) { MATCH (c)-[:INVOKES]->(:Method)-[:ENTRY]->(e)
  MERGE (c)-[r:CALL_FLOW]->(e) ON CREATE SET r.app_id = $app, r.stitched = true } IN TRANSACTIONS OF 2000 ROWS"""),
    ("RETURN / RETURN_FLOW", """MATCH (c:Statement {cross_batch: true}) WHERE c.app_id = $app
CALL (c) { MATCH (c)-[:INVOKES]->(:Method)-[:HAS_STATEMENT]->(x:Statement)
  WHERE x.opcode STARTS WITH 'return' OR x.opcode STARTS WITH 'throw'
  MERGE (x)-[f:RETURN_FLOW]->(c) ON CREATE SET f.app_id = $app, f.stitched = true
  FOREACH (_ IN CASE WHEN x.opcode STARTS WITH 'return' AND x.opcode <> 'return-void' THEN [1] ELSE [] END |
    MERGE (x)-[r:RETURN]->(c) ON CREATE SET r.app_id = $app, r.stitched = true) } IN TRANSACTIONS OF 2000 ROWS"""),
]


def _chunks(rows: list, size: int) -> Iterable[list]:
    for i in range(0, len(rows), size):
        yield rows[i:i + size]


def _clean(props: dict[str, Any]) -> dict[str, Any]:
    # Neo4j rejects empty lists of unknown type and null map values are pointless.
    return {k: v for k, v in props.items() if v is not None and v != []}


def load(g: APG, uri: str, user: str, password: str, database: str | None = None,
         batch_size: int = 5000, replace: bool = True, log=print) -> None:
    from neo4j import GraphDatabase

    driver = GraphDatabase.driver(uri, auth=(user, password))
    try:
        with driver.session(database=database) as s:
            for q in SCHEMA:
                s.run(q).consume()
            if replace:
                log(f"[neo4j] removing previous graph for {g.app_id}")
                s.run(
                    "MATCH (n:APG {app_id: $app}) "
                    "CALL { WITH n DETACH DELETE n } IN TRANSACTIONS OF 10000 ROWS",
                    app=g.app_id,
                ).consume()

            for label in NODE_LABELS:
                rows = [_clean(p) for p in g.nodes.get(label, {}).values()]
                if not rows:
                    continue
                q = f"UNWIND $rows AS row MERGE (n:APG {{uid: row.uid}}) SET n:{label}, n += row"
                for batch in _chunks(rows, batch_size):
                    s.execute_write(lambda tx, b=batch: tx.run(q, rows=b).consume())
                log(f"[neo4j] {label}: {len(rows)} nodes")

            for rel, edges in g.edges.items():
                rows = [{"s": a, "e": b, "p": _clean(p)} for a, b, p in edges]
                q = (f"UNWIND $rows AS row MATCH (a:APG {{uid: row.s}}) MATCH (b:APG {{uid: row.e}}) "
                     f"CREATE (a)-[r:{rel}]->(b) SET r = row.p, r.app_id = a.app_id")
                for batch in _chunks(rows, batch_size):
                    s.execute_write(lambda tx, b=batch: tx.run(q, rows=b).consume())
                log(f"[neo4j] {rel}: {len(rows)} edges")
    finally:
        driver.close()


def load_csv_stream(in_dir, uri: str, user: str, password: str, database: str | None = None,
                    batch_size: int = 5000, log=print) -> None:
    """Load an exported CSV folder into Neo4j batch by batch (see export.iter_csv).

    Same result as ``load(read_csv(in_dir), ...)``, but never holds the whole graph in
    memory, so it works for graphs larger than RAM (PayPal: 12 GB of CSV).
    """
    from collections import Counter
    from neo4j import GraphDatabase
    from .export import csv_app_id, iter_csv

    app_id = csv_app_id(in_dir)
    driver = GraphDatabase.driver(uri, auth=(user, password))
    counts: Counter = Counter()
    current = None
    try:
        with driver.session(database=database) as s:
            for q in SCHEMA:
                s.run(q).consume()
            log(f"[neo4j] removing previous graph for {app_id}")
            s.run(
                "MATCH (n:APG {app_id: $app}) "
                "CALL { WITH n DETACH DELETE n } IN TRANSACTIONS OF 10000 ROWS",
                app=app_id,
            ).consume()
            for kind, name, rows in iter_csv(in_dir, batch_size):
                if current and current != (kind, name):
                    log(f"[neo4j] {current[1]}: {counts[current]} {current[0]}")
                current = (kind, name)
                if kind == "nodes":
                    q = f"UNWIND $rows AS row MERGE (n:APG {{uid: row.uid}}) SET n:{name}, n += row"
                    batch = [_clean(r) for r in rows]
                else:
                    q = (f"UNWIND $rows AS row MATCH (a:APG {{uid: row.s}}) MATCH (b:APG {{uid: row.e}}) "
                         f"CREATE (a)-[r:{name}]->(b) SET r = row.p, r.app_id = a.app_id")
                    batch = [{"s": r["s"], "e": r["e"], "p": _clean(r["p"])} for r in rows]
                s.execute_write(lambda tx, b=batch: tx.run(q, rows=b).consume())
                counts[current] += len(rows)
            if current:
                log(f"[neo4j] {current[1]}: {counts[current]} {current[0]}")
    finally:
        driver.close()


def _is_weak(row: dict) -> bool:
    return row.get("level") == "overview" or (row.get("is_external") is True
                                              and not row.get("has_statements"))


def load_many(dirs, uri: str, user: str, password: str, database: str | None = None,
              batch_size: int = 5000, log=print) -> None:
    """Load several CSV folders of one app as one graph: two-level builds (detail batches
    plus the overview). Nodes of every folder first, then edges, then the batches are
    stitched together. Replaces any previous graph of the app.
    """
    from collections import Counter
    from neo4j import GraphDatabase
    from .export import csv_app_id, iter_csv

    dirs = list(dirs)
    apps = {csv_app_id(d) for d in dirs}
    if len(apps) != 1:
        raise ValueError(f"folders belong to different apps: {sorted(apps)}")
    app_id = apps.pop()
    driver = GraphDatabase.driver(uri, auth=(user, password))
    try:
        with driver.session(database=database) as s:
            for q in SCHEMA:
                s.run(q).consume()
            log(f"[neo4j] removing previous graph for {app_id}")
            s.run("MATCH (n:APG {app_id: $app}) "
                  "CALL { WITH n DETACH DELETE n } IN TRANSACTIONS OF 10000 ROWS", app=app_id).consume()
            for phase in ("nodes", "edges"):
                for d in dirs:
                    counts: Counter = Counter()
                    for kind, name, rows in iter_csv(d, batch_size):
                        if kind != phase:
                            if phase == "nodes":
                                break               # node files come first
                            continue
                        if kind == "nodes":
                            rows = [_clean(r) for r in rows]
                            weak = [r for r in rows if _is_weak(r)]
                            strong = [r for r in rows if not _is_weak(r)]
                            for q, b in ((_STRONG_NODE % name, strong), (_WEAK_NODE % name, weak)):
                                if b:
                                    s.execute_write(lambda tx, q=q, b=b: tx.run(q, rows=b).consume())
                        else:
                            verb = "MERGE" if name in SHARED_EDGES else "CREATE"
                            q = (f"UNWIND $rows AS row MATCH (a:APG {{uid: row.s}}) MATCH (b:APG {{uid: row.e}}) "
                                 f"{verb} (a)-[r:{name}]->(b) SET r += row.p, r.app_id = a.app_id")
                            b = [{"s": r["s"], "e": r["e"], "p": _clean(r["p"])} for r in rows]
                            s.execute_write(lambda tx, q=q, b=b: tx.run(q, rows=b).consume())
                        counts[name] += len(rows)
                    log(f"[neo4j] {d}: {phase} " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
            stitch_batches(s, app_id, log)
    finally:
        driver.close()


def stitch_batches(session, app_id: str, log=print) -> None:
    for name, q in STITCH:
        session.run(q, app=app_id).consume()
        n = session.run(f"MATCH ()-[r:{name.split()[0]} {{stitched: true}}]->() WHERE r.app_id = $app "
                        "RETURN count(r) AS n", app=app_id).single()["n"]
        log(f"[neo4j] stitched {name}: {n}")
