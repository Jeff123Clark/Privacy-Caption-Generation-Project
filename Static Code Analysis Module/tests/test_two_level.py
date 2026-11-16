"""Two-level build on input/APK/sample.apk (F-Droid): overview, detail selection, batches.

The Neo4j side (load_many + stitching) was checked against a full build of the same APK:
identical PPG set, reasons, flows and reachability. This test covers the parts that run
without a database. Takes ~1 minute.
"""

from pathlib import Path

import pytest

from apg.builder import APGBuilder, BuildOptions
from apg.dexscan import read_overview
from apg.overview import AppOverview, partition

SAMPLE = Path(__file__).resolve().parents[1] / "input" / "APK" / "sample.apk"

pytestmark = [pytest.mark.slow,
              pytest.mark.skipif(not SAMPLE.exists(), reason="sample.apk not present")]

SEEDS = ["org.fdroid.fdroid.nearby.SwapWorkflowActivity", "org.fdroid.fdroid.data.Apk"]


@pytest.fixture(scope="module")
def app():
    return AppOverview(SAMPLE)


def test_overview_reads_the_whole_apk(app):
    ov = app.ov
    assert len(ov.classes) > 15_000 and ov.n_calls > 300_000
    main = ov._ids["Lorg/fdroid/fdroid/views/main/MainActivity;"]
    assert app.is_app(main)
    eps = app.entrypoints()
    names = {ov.name(m) for m in eps}
    assert "Lorg/fdroid/fdroid/views/main/MainActivity;->onCreate(Landroid/os/Bundle;)V" in names


def test_selection_adds_callers_and_callees(app):
    sel = app.select(SEEDS, hops=1)
    assert sel["seed_units"] >= 2          # + classes implementing TextWatcher / location callbacks
    assert sel["by_hop"][1] > 0
    # Inner classes and lambdas belong to their top-level class, so units are top-level only.
    assert all("$" not in u for u in sel["units"])
    batches = partition(sel["units"], sel["size"], batch_units=20_000)
    assert sum(len(b) for b in batches) == len(sel["units"]) and len(batches) > 1


def test_batch_marks_calls_into_other_batches(tmp_path):
    peers = tmp_path / "peers.txt"
    peers.write_text("org.fdroid.fdroid.views.PreferencesFragment\norg.fdroid.fdroid.Preferences\n")
    b = APGBuilder(SAMPLE, BuildOptions(include=("org.fdroid.fdroid.views.PreferencesFragment",),
                                        peers=(f"@{peers}",), with_source=False, with_tables=False))
    g = b.build()
    cross = [uid for uid, s in g.nodes["Statement"].items() if s.get("cross_batch")]
    assert cross, "calls into the other batch's classes are marked"
    # ARG edges point at the other batch's Parameter uids (joined when loaded into Neo4j)
    callee = {s: d for s, d, _ in g.edges["INVOKES"]}
    args = [(p["call_site"], d) for _, d, p in g.edges["ARG"] if p["call_site"] in set(cross)]
    assert args and all(d.rsplit("#", 1)[0] == callee[cs] for cs, d in args)
    sigs = {g.nodes["Method"][callee[cs]]["signature"] for cs, _ in args}
    assert all(s.startswith("Lorg/fdroid/fdroid/Preferences;") for s in sigs)


def test_dexscan_matches_androguard_signatures():
    ov = read_overview(SAMPLE)
    sig = "Lorg/fdroid/fdroid/views/main/MainActivity;->onCreate(Landroid/os/Bundle;)V"
    assert sig in ov._ids and ov._ids[sig] in ov.method_flags
