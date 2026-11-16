"""CSV export / import of an APG.

Files use neo4j-admin import headers so they can be bulk-imported directly, while
staying readable with pandas:

  nodes_<Label>.csv   uid:ID, app_id, prop[:type]..., :LABEL
  edges_<TYPE>.csv    :START_ID, :END_ID, :TYPE, prop[:type]...

List properties are ``;``-joined (header ``prop:string[]``). Missing values are
written as unquoted empty fields and real empty strings as ``""`` (csv.QUOTE_NOTNULL),
which neo4j-admin also reads as null vs "". This matters for ``Method.param_types``,
which is "" for no-argument methods exactly like the Document Analysis CSVs.
Files can be gzip-compressed (``.csv.gz``, about 10x smaller); every reader here and
neo4j-admin accept both.
Requires Python 3.12+.
"""

from __future__ import annotations

import csv
import gzip
import json
from pathlib import Path
from typing import Any

from .graph import APG

ARRAY_DELIM = ";"
csv.field_size_limit(1 << 30)


def _files(d: Path, prefix: str) -> list[Path]:
    """nodes_*.csv / edges_*.csv files of a folder, plain or gzip-compressed."""
    return sorted(list(d.glob(f"{prefix}_*.csv")) + list(d.glob(f"{prefix}_*.csv.gz")))


def _name(path: Path, prefix: str) -> str:
    return path.name.split(".", 1)[0][len(prefix) + 1:]


def _open(path: Path, mode: str = "r"):
    if path.suffix == ".gz":
        return gzip.open(path, mode + "t", newline="", encoding="utf-8", compresslevel=6)
    return open(path, mode, newline="", encoding="utf-8")


def _infer_type(values) -> str:
    for v in values:
        if v is None:
            continue
        if isinstance(v, bool):
            return "boolean"
        if isinstance(v, int):
            return "long"
        if isinstance(v, float):
            return "double"
        if isinstance(v, (list, tuple)):
            return "string[]"
        return "string"
    return "string"


def _fmt(v: Any, t: str) -> str | None:
    if v is None:
        return None
    if t == "string[]":
        return ARRAY_DELIM.join(str(x) for x in v)
    if t == "boolean":
        return "true" if v else "false"
    return str(v)


def _header(name: str, t: str) -> str:
    return name if t == "string" else f"{name}:{t}"


def write_csv(g: APG, out_dir: str | Path, summary: dict[str, Any] | None = None,
              compress: bool = False) -> Path:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    ext = ".csv.gz" if compress else ".csv"
    for label, nodes in g.nodes.items():
        rows = list(nodes.values())
        keys = [k for k in dict.fromkeys(k for r in rows for k in r) if k != "uid"]
        types = {k: _infer_type(r.get(k) for r in rows) for k in keys}
        with _open(out / f"nodes_{label}{ext}", "w") as f:
            w = csv.writer(f, quoting=csv.QUOTE_NOTNULL)
            w.writerow(["uid:ID"] + [_header(k, types[k]) for k in keys] + [":LABEL"])
            for r in rows:
                w.writerow([r["uid"]] + [_fmt(r.get(k), types[k]) for k in keys] + [f"APG;{label}"])
    for rel, edges in g.edges.items():
        keys = list(dict.fromkeys(k for _, _, p in edges for k in p))
        types = {k: _infer_type(p.get(k) for _, _, p in edges) for k in keys}
        with _open(out / f"edges_{rel}{ext}", "w") as f:
            w = csv.writer(f, quoting=csv.QUOTE_NOTNULL)
            w.writerow([":START_ID", ":END_ID", ":TYPE"] + [_header(k, types[k]) for k in keys])
            for s, d, p in edges:
                w.writerow([s, d, rel] + [_fmt(p.get(k), types[k]) for k in keys])
    if summary is not None:
        (out / "apg_summary.json").write_text(json.dumps(summary, indent=2, default=str))
    return out


def _parse(v: str | None, t: str) -> Any:
    if v is None:
        return None
    if t == "string":
        return v
    if v == "":
        return None
    if t == "string[]":
        return v.split(ARRAY_DELIM)
    if t == "boolean":
        return v == "true"
    if t in ("long", "int"):
        return int(v)
    if t in ("double", "float"):
        return float(v)
    return v


def _split_header(h: str) -> tuple[str, str]:
    name, _, t = h.partition(":")
    return name, t or "string"


def read_csv(in_dir: str | Path) -> APG:
    """Rebuild an APG from a directory written by :func:`write_csv`."""
    d = Path(in_dir)
    g: APG | None = None
    for path in _files(d, "nodes"):
        label = _name(path, "nodes")
        with _open(path) as f:
            r = csv.reader(f, quoting=csv.QUOTE_NOTNULL)
            header = next(r)
            cols = [_split_header(h) for h in header]
            for row in r:
                props = {}
                for (name, t), v in zip(cols, row):
                    if name in ("uid", "") or t in ("ID", "LABEL"):
                        continue
                    props[name] = _parse(v, t)
                if g is None:
                    g = APG(props["app_id"])
                props.pop("app_id", None)
                g.add_node(label, row[0], **props)
    if g is None:
        raise FileNotFoundError(f"no nodes_*.csv in {d}")
    for path in _files(d, "edges"):
        with _open(path) as f:
            r = csv.reader(f, quoting=csv.QUOTE_NOTNULL)
            cols = [_split_header(h) for h in next(r)]
            for row in r:
                props = {name: _parse(v, t) for (name, t), v in zip(cols[3:], row[3:])}
                g.add_edge(row[2], row[0], row[1], **{k: v for k, v in props.items() if v is not None})
    return g


def iter_csv(in_dir: str | Path, batch_size: int = 5000):
    """Stream a directory written by :func:`write_csv` in batches, without building an APG.

    Yields ``("nodes", label, rows)`` for every node file first, then
    ``("edges", rel_type, rows)``. Node rows are property dicts (with ``uid`` and
    ``app_id``); edge rows are ``{"s": start uid, "e": end uid, "p": properties}``.
    Memory stays at one batch, whatever the size of the graph.
    """
    d = Path(in_dir)
    node_files = _files(d, "nodes")
    if not node_files:
        raise FileNotFoundError(f"no nodes_*.csv in {d}")
    for path in node_files:
        label = _name(path, "nodes")
        with _open(path) as f:
            r = csv.reader(f, quoting=csv.QUOTE_NOTNULL)
            cols = [_split_header(h) for h in next(r)]
            batch = []
            for row in r:
                props = {"uid": row[0]}
                for (name, t), v in zip(cols, row):
                    if name in ("uid", "") or t in ("ID", "LABEL"):
                        continue
                    props[name] = _parse(v, t)
                batch.append(props)
                if len(batch) >= batch_size:
                    yield "nodes", label, batch
                    batch = []
            if batch:
                yield "nodes", label, batch
    for path in _files(d, "edges"):
        with _open(path) as f:
            r = csv.reader(f, quoting=csv.QUOTE_NOTNULL)
            cols = [_split_header(h) for h in next(r)]
            batch, rel = [], None
            for row in r:
                rel = row[2]
                props = {name: _parse(v, t) for (name, t), v in zip(cols[3:], row[3:])}
                batch.append({"s": row[0], "e": row[1], "p": {k: v for k, v in props.items() if v is not None}})
                if len(batch) >= batch_size:
                    yield "edges", rel, batch
                    batch = []
            if batch:
                yield "edges", rel, batch


def csv_app_id(in_dir: str | Path) -> str:
    """The app_id of an exported APG (read from nodes_App.csv)."""
    d = Path(in_dir)
    path = d / "nodes_App.csv" if (d / "nodes_App.csv").exists() else d / "nodes_App.csv.gz"
    with _open(path) as f:
        r = csv.reader(f, quoting=csv.QUOTE_NOTNULL)
        header = next(r)
        row = next(r)
    return row[header.index("app_id")]
