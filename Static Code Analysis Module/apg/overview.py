"""Two-level build: a light overview of the whole app plus detailed APGs where it matters.

Level 1 - overview (whole APK, from dexscan.py, a few GB even for PayPal):
    every method of the app's own code (origin app / unknown), who it calls, which methods
    it overrides, and which are entry points. Loaded into Neo4j as Method nodes and
    CALLS / OVERRIDES edges (property ``level = 'overview'``), so reachability and call
    chains (P7) see the whole app.

Level 2 - detail (androguard, full APG: statements, CFG, data flow):
    the seed classes (those that read a known sensitive source, from
    scripts/prescan_apk.py) plus the app classes that call them or that they call, up to
    ``hops`` steps away in the overview call graph. Units are top-level classes: a unit
    keeps its inner classes and Kotlin lambdas (``Foo$1``, ``Foo$$ExternalSyntheticLambda0``).
    The detail classes are split into batches small enough to build in memory; each batch
    is built in its own process and the batches are joined again when loaded into Neo4j
    (see neo4j_loader.stitch_batches).
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict, deque
from pathlib import Path
from typing import Any

from .dexscan import Overview, read_overview

ACC_PRIVATE, ACC_STATIC, ACC_INTERFACE, ACC_ABSTRACT = 0x2, 0x8, 0x200, 0x400

# Classes that receive personal data by implementing a framework callback (P3d, P3g-4 in
# ppg_build.cypher). They call nothing sensitive, so the pre-scan does not find them.
CALLBACK_SEED_TYPES = {
    "Landroid/text/TextWatcher;", "Landroid/location/LocationListener;",
    "Lcom/google/android/gms/location/LocationCallback;",
}
_CALLBACK_RE = re.compile(r"^on[A-Z]")


def _outer(dname: str) -> str:
    """Lcom/a/B$C; -> Lcom/a/B;"""
    return dname.split("$", 1)[0].rstrip(";") + ";"


def _dots(dname: str) -> str:
    return dname[1:-1].replace("/", ".")


def _ddesc(dotted: str) -> str:
    return "L" + dotted.replace(".", "/") + ";"


class AppOverview:
    """Overview plus app identity, origins, call resolution and entry points."""

    def __init__(self, apk_path, ov: Overview | None = None):
        from androguard.core import apk as _apk
        from .builder import CALLBACK_NAMES, FRAMEWORK_CALLBACK_CLASSES
        from .libraries import OriginClassifier, match_library, vendor_prefixes

        self.apk_path = Path(apk_path)
        a = _apk.APK(str(apk_path))              # manifest only; the DEX is read by dexscan
        sha = hashlib.sha256(self.apk_path.read_bytes()).hexdigest()
        self.package = a.get_package()
        self.app_id = f"{self.package}@{a.get_androidversion_code() or 0}-{sha[:8]}"
        self.components: dict[str, str] = {}     # dotted class -> component type
        for kind, names in (("activity", a.get_activities()), ("service", a.get_services()),
                            ("receiver", a.get_receivers()), ("provider", a.get_providers())):
            for n in names or ():
                self.components.setdefault(n, kind)
        prefixes = {self.package, *vendor_prefixes(self.package)}
        prefixes |= {c.rsplit(".", 1)[0] for c in self.components
                     if "." in c and match_library(c) is None}
        self.origins = OriginClassifier(sorted(prefixes))
        self._callback_names = CALLBACK_NAMES
        self._framework_callbacks = FRAMEWORK_CALLBACK_CLASSES
        self.ov = ov or read_overview(apk_path)
        self._origin: dict[int, str] = {}
        # name+descriptor ids per defined class, for override and dispatch lookups
        self.class_keys: dict[int, set[str]] = defaultdict(set)
        for mid in self.ov.method_flags:
            cls, key = self.ov.name(mid).split("->", 1)
            self.class_keys[self.ov.method_cls[mid]].add(key)

    # ------------------------------------------------------------------ basics
    def origin(self, cid: int) -> str:
        o = self._origin.get(cid)
        if o is None:
            o = self._origin[cid] = self.origins.classify(
                _dots(self.ov.name(cid)), cid not in self.ov.classes)[0]
        return o

    def is_app(self, cid: int) -> bool:
        return cid in self.ov.classes and self.origin(cid) in ("app", "unknown")

    def resolve(self, mid: int) -> int:
        """Referenced method -> the method that defines it (walking superclasses in the APK)."""
        ov = self.ov
        if mid in ov.method_flags:
            return mid
        cls, key = ov.name(mid).split("->", 1)
        c = ov._ids.get(cls)
        seen = set()
        while c is not None and c in ov.classes and c not in seen:
            seen.add(c)
            if key in self.class_keys.get(c, ()):
                return ov.method(ov.name(c), key)
            sup = ov.classes[c][0]
            c = sup if sup >= 0 else None
        return mid

    # ------------------------------------------------------------ entry points
    def entrypoints(self) -> dict[int, str]:
        """method id -> entrypoint kind, same rules as APGBuilder._add_overrides_and_entrypoints."""
        ov = self.ov
        self.overrides: dict[int, list[int]] = {}
        memo: dict[int, bool] = {}

        def overridden(mid: int) -> tuple[list[int], bool]:
            """(overridden methods defined in the APK, overrides an external callback?)"""
            cls, key = ov.name(mid).split("->", 1)
            name = key.split("(", 1)[0]
            cid = ov.method_cls[mid]
            sup, itfs, _ = ov.classes[cid]
            todo = ([sup] if sup >= 0 else []) + list(itfs)
            seen, out, ext = set(), [], False
            while todo:
                c = todo.pop(0)
                if c in seen:
                    continue
                seen.add(c)
                if c not in ov.classes:          # external (framework) class
                    cname = _dots(ov.name(c))
                    ext_mid = ov._ids.get(f"{ov.name(c)}->{key}")
                    if ext_mid is not None and ext_mid in ov.method_cls:
                        # Referenced somewhere in the APK, so the framework declares it
                        # (androguard's external methods, as in a full build).
                        out.append(ext_mid)
                        if cname.startswith(("android.", "com.android.")) or cname in self._framework_callbacks:
                            ext = True
                        continue
                    if cname != "java.lang.Object" and (_CALLBACK_RE.match(name) or name in self._callback_names) \
                            and (cname.startswith(("android.", "com.android.")) or cname in self._framework_callbacks
                                 or self.origin(c) == "library"):
                        ext = True
                    continue
                if key in self.class_keys.get(c, ()):
                    out.append(ov.method(ov.name(c), key))
                    continue
                s, i, _ = ov.classes[c]
                if s >= 0:
                    todo.append(s)
                todo.extend(i)
            return out, ext

        def framework_reachable(mid: int) -> bool:
            if mid in memo:
                return memo[mid]
            memo[mid] = False
            targets, ext = self.overrides.get(mid) or (None, None)
            if targets is None:
                targets, ext = overridden(mid)
            res = ext or any(self.origin(ov.method_cls[t]) == "library"
                             or (ov.method_cls[t] in ov.classes and framework_reachable(t))
                             for t in targets)
            memo[mid] = res
            return res

        out: dict[int, str] = {}
        for mid, flags in ov.method_flags.items():
            cid = ov.method_cls[mid]
            if not self.is_app(cid):
                continue
            name = ov.name(mid).split("->", 1)[1].split("(", 1)[0]
            cname = _dots(ov.name(cid))
            ctor = name in ("<init>", "<clinit>")
            if not (ctor or flags & (ACC_STATIC | ACC_PRIVATE)):
                targets, ext = overridden(mid)
                self.overrides[mid] = (targets, ext)
                if framework_reachable(mid):
                    out[mid] = "component_lifecycle" if cname in self.components else "callback"
                    continue
            if ctor and name == "<init>" and cname in self.components:
                out[mid] = "component_init"
        return out

    # ---------------------------------------------------------------- selection
    def unit_graph(self) -> tuple[dict[int, set[int]], dict[int, set[int]], dict[int, int]]:
        """Top-level app classes: callees, callers and code size (16-bit units)."""
        ov = self.ov
        unit_of: dict[int, int] = {}
        size: dict[int, int] = defaultdict(int)
        for cid in ov.classes:
            if self.is_app(cid):
                u = unit_of[cid] = ov.intern(_outer(ov.name(cid)))
                size[u] += ov.code_units.get(cid, 0)
        # Interface / abstract app methods dispatch to their implementations.
        impls: dict[int, set[int]] = defaultdict(set)
        for cid, (sup, itfs, flags) in ov.classes.items():
            if cid in unit_of:
                for p in ([sup] if sup >= 0 else []) + list(itfs):
                    if p in unit_of and ov.classes[p][2] & (ACC_INTERFACE | ACC_ABSTRACT):
                        impls[unit_of[p]].add(unit_of[cid])
        callees: dict[int, set[int]] = defaultdict(set)
        callers: dict[int, set[int]] = defaultdict(set)
        cls_of = ov.method_cls
        for a, b in zip(ov.calls_from, ov.calls_to):
            ua = unit_of.get(cls_of[a])
            ub = unit_of.get(cls_of.get(b, -1))
            if ua is None or ub is None or ua == ub:
                continue
            callees[ua].add(ub)
            callers[ub].add(ua)
            for ui in impls.get(ub, ()) if len(impls.get(ub, ())) <= 3 else ():
                if ui != ua:
                    callees[ua].add(ui)
                    callers[ui].add(ua)
        self.unit_of = unit_of
        return callees, callers, size

    def select(self, seeds: list[str], hops: int = 2, max_units: int = 12_000_000,
               fan_limit: int = 50) -> dict[str, Any]:
        """Detail units: seeds, then callers/callees by hop distance, until max_units of code.

        A unit with more than ``fan_limit`` callers or callees (utility classes, base
        view-models) is added but not expanded further, so one helper does not pull in
        half the app.
        """
        ov = self.ov
        callees, callers, size = self.unit_graph()
        cb_types = {ov._ids[t] for t in CALLBACK_SEED_TYPES if t in ov._ids}
        callback_seeds = [_dots(ov.name(c)) for c, (sup, itfs, _f) in ov.classes.items()
                          if self.is_app(c) and (sup in cb_types or cb_types.intersection(itfs))]
        seed_units = []
        for s in list(seeds) + callback_seeds:
            u = ov._ids.get(_outer(_ddesc(s)))
            if u is not None and u in size and u not in seed_units:
                seed_units.append(u)
        chosen: dict[int, int] = {u: 0 for u in seed_units}       # unit -> hop distance
        total = sum(size[u] for u in seed_units)
        frontier = deque(seed_units)
        dropped = 0
        for hop in range(1, hops + 1):
            nxt: dict[int, int] = {}
            for u in frontier:
                if hop > 1 and len(callers.get(u, ())) + len(callees.get(u, ())) > fan_limit:
                    continue
                for v in callers.get(u, set()) | callees.get(u, set()):
                    if v not in chosen:
                        nxt[v] = nxt.get(v, 0) + 1
            # Most-connected first, so the budget goes to the closest neighbours.
            frontier = deque()
            for v, _links in sorted(nxt.items(), key=lambda kv: -kv[1]):
                if total + size[v] > max_units:
                    dropped += 1
                    continue
                chosen[v] = hop
                total += size[v]
                frontier.append(v)
        by_hop = defaultdict(int)
        for h in chosen.values():
            by_hop[h] += 1
        return {"units": [_dots(ov.name(u)) for u in chosen], "hop": {_dots(ov.name(u)): h for u, h in chosen.items()},
                "size": {_dots(ov.name(u)): size[u] for u in chosen},
                "code_units": total, "by_hop": dict(by_hop), "dropped_for_budget": dropped,
                "seed_units": len(seed_units), "callback_seed_classes": len(callback_seeds),
                "app_units": len(size),
                "app_code_units": sum(size.values())}

    # ------------------------------------------------------------------ export
    def to_apg(self, detail_units: set[str]):
        """Overview of every class in the APK (the app and its bundled SDKs): Method and
        Class nodes, CALLS edges, and OVERRIDES between the app's own methods.

        Calls made by detail classes are left out: their APG already has them, resolved
        from the statements. SDK code is in the overview like in a full build's call graph,
        so an SDK that reads location still shows up (and becomes a PPG).
        """
        from .builder import java_method_info
        from .graph import APG, CLASS, LIBRARY, METHOD, node_uid
        ov = self.ov
        eps = self.entrypoints()
        g = APG(self.app_id)
        uid = lambda mid: node_uid(self.app_id, "M", ov.name(mid))
        detail_cls = {cid for cid in ov.classes if _dots(_outer(ov.name(cid))) in detail_units}

        def class_node(cid: int) -> str:
            dname = ov.name(cid)
            u = node_uid(self.app_id, "C", dname)
            if not g.has_node(CLASS, u):
                jname = _dots(dname)
                origin, lib, lib_cat = self.origins.classify(jname, cid not in ov.classes)
                g.add_node(CLASS, u, name=jname, dalvik_name=dname, is_external=cid not in ov.classes,
                           origin=origin, library=lib, library_category=lib_cat, level="overview")
                g.add_edge("HAS_CLASS", self.app_id, u)
                if lib:
                    lu = node_uid(self.app_id, "L", lib)
                    if not g.has_node(LIBRARY, lu):
                        g.add_node(LIBRARY, lu, name=lib, category=lib_cat)
                        g.add_edge("USES_LIBRARY", self.app_id, lu)
                    g.add_edge("BELONGS_TO", u, lu)
            return u

        def node(mid: int) -> str:
            u = uid(mid)
            if not g.has_node(METHOD, u):
                cls, key = ov.name(mid).split("->", 1)
                name, desc = key.split("(", 1)
                desc = "(" + desc
                cid = ov.method_cls[mid]
                flags = ov.method_flags.get(mid)
                g.add_edge("HAS_METHOD", class_node(cid), u)
                g.add_node(METHOD, u, name=name, signature=ov.name(mid), descriptor=desc,
                           **java_method_info(cls, name, desc), is_external=flags is None,
                           origin=self.origin(cid), is_static=bool(flags and flags & ACC_STATIC),
                           is_constructor=name in ("<init>", "<clinit>"),
                           is_entrypoint=mid in eps, entrypoint_kind=eps.get(mid),
                           in_apk=flags is not None, level="overview")
            return u

        for mid in eps:
            node(mid)
        calls: dict[tuple[int, int], int] = defaultdict(int)
        cls_of = ov.method_cls
        for a, b in zip(ov.calls_from, ov.calls_to):
            if cls_of[a] in detail_cls:
                continue
            calls[(a, self.resolve(b))] += 1
        for (a, b), n in calls.items():
            g.add_edge("CALLS", node(a), node(b), count=n, level="overview")
        # API -> permission for framework methods the overview calls (same map as the builder)
        n_perm = 0
        try:
            from androguard.core.api_specific_resources import load_permission_mappings
            from .builder import PERMISSION_MAPPING_API
            from .graph import PERMISSION, node_uid
            mapping = {k.replace(" ", ""): v for k, v in load_permission_mappings(PERMISSION_MAPPING_API).items()}
        except Exception:
            mapping = {}
        for u, props in list(g.nodes.get(METHOD, {}).items()):
            if not props["is_external"]:
                continue
            cls, key = props["signature"].split("->", 1)
            name, desc = key.split("(", 1)
            for perm in mapping.get(f"{cls}-{name}-({desc}", ()):
                pu = node_uid(self.app_id, "Perm", perm)
                if not g.has_node(PERMISSION, pu):
                    g.add_node(PERMISSION, pu, name=perm)
                g.add_edge("API_REQUIRES_PERMISSION", u, pu, source=f"androguard-api{PERMISSION_MAPPING_API}")
                n_perm += 1
        n_over = 0
        # Every override of the app's methods, also for detail classes: a detail batch only
        # sees the parents and framework methods its own classes reference.
        for mid, (targets, _ext) in getattr(self, "overrides", {}).items():
            for t in targets:
                g.add_edge("OVERRIDES", node(mid), node(t), level="overview")
                n_over += 1
        self.stats = {"overview_methods": len(g.nodes.get(METHOD, {})), "overview_calls": len(calls),
                      "overview_overrides": n_over, "entrypoints": len(eps),
                      "overview_api_permissions": n_perm}
        return g


def partition(units: list[str], size: dict[str, int], batch_units: int) -> list[list[str]]:
    """Split detail units into batches of at most batch_units code, keeping packages together."""
    batches, cur, total = [], [], 0
    for u in sorted(units):
        s = size.get(u, 0)
        if cur and total + s > batch_units:
            batches.append(cur)
            cur, total = [], 0
        cur.append(u)
        total += s
    if cur:
        batches.append(cur)
    return batches


def plan(apk_path, seeds_file, out_dir, hops: int = 2, max_units: int = 12_000_000,
         batch_units: int = 3_000_000, log=print) -> dict[str, Any]:
    """Write the overview CSVs and the detail batches for a two-level build of one APK.

    out_dir/
      overview/            level 1 (Neo4j CSV)
      batch_01.txt ...     level 2 classes, one --include file per batch
      detail_classes.txt   all level 2 classes (every batch gets it as --peers)
      plan.json            what was chosen and why
    """
    from .export import write_csv
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    seeds = [l.strip() for l in Path(seeds_file).read_text().splitlines() if l.strip()]
    log(f"[plan] reading {apk_path}")
    app = AppOverview(apk_path)
    ov = app.ov
    log(f"[plan] {len(ov.classes)} classes, {len(ov.method_flags)} methods, {ov.n_calls} calls")
    sel = app.select(seeds, hops=hops, max_units=max_units)
    units = sel["units"]
    log(f"[plan] detail: {len(units)} classes ({sel['code_units']:,} code units) from "
        f"{sel['seed_units']} seed classes; by hop {sel['by_hop']}; "
        f"{sel['dropped_for_budget']} left out for the budget")
    batches = partition(units, sel["size"], batch_units)
    for old in out.glob("batch_*.txt"):
        old.unlink()
    for i, b in enumerate(batches, 1):
        (out / f"batch_{i:02d}.txt").write_text("\n".join(b) + "\n")
    (out / "detail_classes.txt").write_text("\n".join(sorted(units)) + "\n")
    g = app.to_apg(set(units))
    write_csv(g, out / "overview", {"app_id": app.app_id, "apk": str(apk_path), "level": "overview",
                                    **app.stats}, compress=True)
    # write_csv needs an App node for csv_app_id(); the detail batches also write one.
    (out / "overview" / "nodes_App.csv").write_text(
        f'"uid:ID","app_id",":LABEL"\n"{app.app_id}","{app.app_id}","APG;App"\n')
    info = {"app_id": app.app_id, "apk": str(apk_path), "seeds": len(seeds), "hops": hops,
            "max_units": max_units, "batch_units": batch_units, "batches": len(batches),
            **{k: v for k, v in sel.items() if k not in ("units", "hop", "size")},
            **app.stats, "hop_of_class": sel["hop"]}
    (out / "plan.json").write_text(json.dumps(info, indent=1))
    log(f"[plan] overview: {app.stats}")
    log(f"[plan] {len(batches)} detail batches written to {out}")
    return info
