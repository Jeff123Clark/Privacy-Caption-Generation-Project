"""Command line entry point.

    python -m apg build input/APK/sample.apk -o output/apg
    python -m apg build input/APK/ -o output/apg --neo4j          # every APK in a folder
    python -m apg load output/apg/<app_id> --neo4j-uri bolt://localhost:7687

One command, APK in, PPG files out (password from NEO4J_PASSWORD):
    python -m apg pipeline input/APK/PayPal_10.18.0_APKPure.apk

Two-level build for very large APKs (overview of the whole app + detail where it matters),
step by step:
    python scripts/prescan_apk.py <apk> --classes-out seeds.txt
    python -m apg plan <apk> --seeds seeds.txt -o output/twolevel/<name>
    python -m apg build-plan output/twolevel/<name>
    python -m apg load output/twolevel/<name>

Neo4j credentials default to the NEO4J_URI / NEO4J_USER / NEO4J_PASSWORD env vars.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


def _quiet_androguard(verbose: bool) -> None:
    try:
        from loguru import logger
        logger.remove()
        logger.add(sys.stderr, level="INFO" if verbose else "ERROR")
    except ImportError:
        pass


def _neo4j_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--neo4j-uri", default=os.environ.get("NEO4J_URI", "bolt://localhost:7687"))
    p.add_argument("--neo4j-user", default=os.environ.get("NEO4J_USER", "neo4j"))
    p.add_argument("--neo4j-password", default=os.environ.get("NEO4J_PASSWORD"))
    p.add_argument("--neo4j-database", default=os.environ.get("NEO4J_DATABASE"))


def _load(g, args) -> None:
    from .neo4j_loader import load
    if not args.neo4j_password:
        sys.exit("Neo4j password missing: pass --neo4j-password or set NEO4J_PASSWORD")
    load(g, args.neo4j_uri, args.neo4j_user, args.neo4j_password, args.neo4j_database)


def cmd_build(args) -> None:
    from .builder import APGBuilder, BuildOptions
    from .export import write_csv

    src = Path(args.apk)
    apks = sorted(src.glob("*.apk")) if src.is_dir() else [src]
    if not apks:
        sys.exit(f"no .apk files found at {src}")
    opts = BuildOptions(stmt_scope=args.stmt_scope,
                        include_exception_edges=not args.no_exception_edges,
                        include_api_permission_mapping=not args.no_api_permissions,
                        with_source=not args.no_source,
                        with_tables=not args.no_tables,
                        include=tuple(x for x in (args.include or "").split(",") if x.strip()),
                        peers=tuple(x for x in (getattr(args, "peers", None) or "").split(",") if x.strip()))
    for apk in apks:
        print(f"[apg] analysing {apk}")
        b = APGBuilder(apk, opts)
        g = b.build()
        summary = {"app_id": g.app_id, "apk": str(apk), "options": vars(opts), **b.stats}
        out = Path(args.out) / g.app_id.replace("/", "_")
        if not args.no_csv:
            write_csv(g, out, summary, compress=args.gzip)
            print(f"[apg] wrote CSVs to {out}")
        print(json.dumps({k: summary[k] for k in ("app_id", "nodes", "edges")}, indent=1))
        if args.neo4j:
            _load(g, args)


def _plan_dirs(plan_dir: Path) -> list[Path]:
    """Detail batch folders, then the overview, of a two-level build."""
    detail = sorted({p.parent for p in plan_dir.glob("detail_*/*/nodes_App.csv*")})
    return detail + [plan_dir / "overview"]


def cmd_load(args) -> None:
    # Streams the CSVs in batches, so graphs larger than memory load too.
    from .export import csv_app_id
    from .neo4j_loader import load_csv_stream, load_many
    if not args.neo4j_password:
        sys.exit("Neo4j password missing: pass --neo4j-password or set NEO4J_PASSWORD")
    plan_dir = Path(args.csv_dir)
    if (plan_dir / "plan.json").exists():
        info = json.loads((plan_dir / "plan.json").read_text())
        dirs = _plan_dirs(plan_dir)
        built = len(dirs) - 1
        if built < info["batches"]:
            sys.exit(f"only {built} of {info['batches']} detail batches are built; run build-plan first")
        print(f"[apg] loading two-level build of {info['app_id']}: {built} detail batches + overview",
              flush=True)
        load_many(dirs, args.neo4j_uri, args.neo4j_user, args.neo4j_password, args.neo4j_database,
                  log=lambda m: print(m, flush=True))
        return
    print(f"[apg] streaming {csv_app_id(args.csv_dir)} from {args.csv_dir}", flush=True)
    load_csv_stream(args.csv_dir, args.neo4j_uri, args.neo4j_user, args.neo4j_password,
                    args.neo4j_database, log=lambda m: print(m, flush=True))


def cmd_plan(args) -> None:
    from .overview import plan
    plan(args.apk, args.seeds, args.out, hops=args.hops, max_units=args.max_units,
         batch_units=args.batch_units, log=lambda m: print(m, flush=True))


def cmd_build_plan(args) -> None:
    """Build every detail batch of a plan, each in its own process (memory is freed between)."""
    import subprocess
    import time
    plan_dir = Path(args.plan_dir)
    info = json.loads((plan_dir / "plan.json").read_text())
    batches = sorted(plan_dir.glob("batch_*.txt"))
    for i, bfile in enumerate(batches, 1):
        out = plan_dir / f"detail_{bfile.stem[6:]}"
        if list(out.glob("*/nodes_App.csv*")) and not args.rebuild:
            print(f"[apg] batch {i}/{len(batches)} already built ({out})", flush=True)
            continue
        cmd = [sys.executable, "-m", "apg", "build", info["apk"], "-o", str(out),
               "--include", f"@{bfile}", "--peers", f"@{plan_dir / 'detail_classes.txt'}",
               "--stmt-scope", args.stmt_scope, "--gzip"]
        print(f"[apg] batch {i}/{len(batches)}: {bfile.name}", flush=True)
        t = time.time()
        r = subprocess.run(cmd)
        if r.returncode:
            sys.exit(f"batch {bfile.name} failed (exit {r.returncode}); rerun build-plan to resume")
        print(f"[apg] batch {i}/{len(batches)} done in {(time.time() - t) / 60:.1f} min", flush=True)
    print(f"[apg] all {len(batches)} batches built; next: python -m apg load {plan_dir}", flush=True)


def cmd_pipeline(args) -> None:
    """APK -> per-method APGs -> Neo4j -> Cypher -> one JSON file per PPG.

    Steps: pre-scan, plan (overview + detail batches), build the batches, load into Neo4j,
    build the PPGs, then delete the intermediate CSVs (unless --keep-files). Rerunning
    continues where a previous run stopped.
    """
    import shutil
    import subprocess
    import time
    from .export import csv_app_id
    from .neo4j_loader import load_many

    if not args.neo4j_password:
        sys.exit("Neo4j password missing: set NEO4J_PASSWORD (or pass --neo4j-password)")
    from neo4j import GraphDatabase
    try:
        with GraphDatabase.driver(args.neo4j_uri, auth=(args.neo4j_user, args.neo4j_password)) as d:
            d.verify_connectivity()
    except Exception as e:  # fail before an hour of building, not after
        sys.exit(f"cannot connect to Neo4j at {args.neo4j_uri}: {e}")

    apk = Path(args.apk)
    work = Path(args.out or f"output/twolevel/{apk.stem}")
    work.mkdir(parents=True, exist_ok=True)
    here = Path(__file__).resolve().parent.parent
    py = sys.executable
    free = shutil.disk_usage(work).free / 1e9
    print(f"[pipeline] {apk} -> {work} ({free:.0f} GB free on this disk)", flush=True)
    if Path("/mnt/c").is_dir():
        # Under WSL the Linux disk is a file on C:, which grows as Linux writes.
        c_free = shutil.disk_usage("/mnt/c").free / 1e9
        print(f"[pipeline] WSL: {c_free:.0f} GB free on Windows C:, where the Linux disk file grows", flush=True)
        if c_free < args.min_free_gb:
            sys.exit(f"[pipeline] only {c_free:.0f} GB free on C:; a large APK can need 20-40 GB "
                     f"(Neo4j + temporary files). Free space or pass --min-free-gb 0 to go on anyway")

    def run(step: str, cmd: list[str]) -> None:
        print(f"[pipeline] {step}", flush=True)
        t = time.time()
        env = {**os.environ, "NEO4J_PASSWORD": args.neo4j_password}
        if subprocess.run(cmd, env=env).returncode:
            sys.exit(f"[pipeline] {step} failed; rerun the same command to continue")
        print(f"[pipeline] {step} done in {(time.time() - t) / 60:.1f} min", flush=True)

    seeds = work / "seeds.txt"
    if not seeds.exists() or args.replan:
        run("1/5 pre-scan: classes that read sensitive data",
            [py, str(here / "scripts" / "prescan_apk.py"), str(apk), "--classes-out", str(seeds)])
    if not (work / "plan.json").exists() or args.replan:
        run("2/5 plan: whole-app overview + detail batches",
            [py, "-m", "apg", "plan", str(apk), "--seeds", str(seeds), "-o", str(work),
             "--hops", str(args.hops), "--max-units", str(args.max_units),
             "--batch-units", str(args.batch_units)])
    run("3/5 build: per-method APGs, batch by batch", [py, "-m", "apg", "build-plan", str(work)])

    dirs = _plan_dirs(work)
    app_id = csv_app_id(dirs[0])
    print("[pipeline] 4/5 load into Neo4j", flush=True)
    t = time.time()
    load_many(dirs, args.neo4j_uri, args.neo4j_user, args.neo4j_password, args.neo4j_database,
              log=lambda m: print(m, flush=True))
    print(f"[pipeline] 4/5 load done in {(time.time() - t) / 60:.1f} min", flush=True)

    run("5/5 PPGs: Cypher filters the method APGs",
        [py, str(here / "scripts" / "build_ppg.py"), app_id, "--export", args.export,
         "--neo4j-uri", args.neo4j_uri, "--neo4j-user", args.neo4j_user]
        + (["--with-user-input"] if args.with_user_input else []))
    if not args.keep_files:
        for d in [*work.glob("detail_*"), work / "overview"]:
            shutil.rmtree(d, ignore_errors=True)
        print("[pipeline] deleted the intermediate CSVs (the graph is in Neo4j)", flush=True)
    print(f"[pipeline] done: PPG files in {Path(args.export) / app_id}", flush=True)


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(prog="apg", description="Build App Property Graphs from APKs")
    ap.add_argument("-v", "--verbose", action="store_true", help="show androguard logs")
    sub = ap.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("build", help="analyse APK(s) and export the APG")
    b.add_argument("apk", help="APK file or folder of APKs")
    b.add_argument("-o", "--out", default="output/apg", help="output folder (one sub-folder per app)")
    b.add_argument("--stmt-scope", default="nonlib", choices=["app", "nonlib", "all", "none"],
                   help="which classes get statement-level CFG/data-flow "
                        "(nonlib = app + unrecognised code; default)")
    b.add_argument("--no-exception-edges", action="store_true")
    b.add_argument("--no-api-permissions", action="store_true",
                   help="skip androguard's API->permission mapping")
    b.add_argument("--no-source", action="store_true",
                   help="skip decompiled Java on methods (used for PRCS / caption code segments)")
    b.add_argument("--no-tables", action="store_true",
                   help="skip the per-method AST/CFG/data-flow/call tables on Method nodes")
    b.add_argument("--include", metavar="PKG[,PKG...]",
                   help="only analyse these packages or classes (comma-separated; @FILE reads one per "
                        "line, e.g. from scripts/prescan_apk.py --classes-out). The rest of the APK "
                        "is treated as external. For APKs too large to build whole")
    b.add_argument("--peers", metavar="PKG[,PKG...]",
                   help="two-level builds: classes built in the other detail batches (@FILE)")
    b.add_argument("--no-csv", action="store_true")
    b.add_argument("--gzip", action="store_true", help="write compressed .csv.gz files (about 10x smaller)")
    b.add_argument("--neo4j", action="store_true", help="also load into Neo4j")
    _neo4j_args(b)
    b.set_defaults(func=cmd_build)

    pl = sub.add_parser("plan", help="two-level build, step 1: whole-app overview and detail batches")
    pl.add_argument("apk")
    pl.add_argument("--seeds", required=True,
                    help="classes that read sensitive sources (scripts/prescan_apk.py --classes-out)")
    pl.add_argument("-o", "--out", required=True, help="plan folder, e.g. output/twolevel/paypal")
    pl.add_argument("--hops", type=int, default=2, help="caller/callee steps around the seeds (default 2)")
    pl.add_argument("--max-units", type=int, default=12_000_000,
                    help="total detail code, in 16-bit code units (default 12M, about half of PayPal)")
    pl.add_argument("--batch-units", type=int, default=3_000_000,
                    help="code per detail batch; about 3M fits in 16 GB (default)")
    pl.set_defaults(func=cmd_plan)

    bp = sub.add_parser("build-plan", help="two-level build, step 2: build every detail batch")
    bp.add_argument("plan_dir")
    bp.add_argument("--stmt-scope", default="nonlib", choices=["app", "nonlib", "all"])
    bp.add_argument("--rebuild", action="store_true", help="rebuild batches that already exist")
    bp.set_defaults(func=cmd_build_plan)

    pp = sub.add_parser("pipeline", help="APK in, PPG files out: every step below in one command")
    pp.add_argument("apk")
    pp.add_argument("-o", "--out", help="working folder (default output/twolevel/<apk name>)")
    pp.add_argument("--export", default="output/ppg", help="where the PPG JSON files go")
    pp.add_argument("--hops", type=int, default=2)
    pp.add_argument("--max-units", type=int, default=12_000_000)
    pp.add_argument("--batch-units", type=int, default=2_000_000)
    pp.add_argument("--replan", action="store_true", help="redo the pre-scan and plan")
    pp.add_argument("--with-user-input", action="store_true",
                    help="also make PPGs from text-input fields (left out by default)")
    pp.add_argument("--keep-files", action="store_true", help="keep the intermediate CSVs")
    pp.add_argument("--min-free-gb", type=float, default=15,
                    help="WSL: stop if Windows C: has less free space than this (default 15)")
    _neo4j_args(pp)
    pp.set_defaults(func=cmd_pipeline)

    ld = sub.add_parser("load", help="load an exported CSV folder (or a two-level plan folder) into Neo4j")
    ld.add_argument("csv_dir")
    _neo4j_args(ld)
    ld.set_defaults(func=cmd_load)

    args = ap.parse_args(argv)
    _quiet_androguard(args.verbose)
    args.func(args)


if __name__ == "__main__":
    main()
