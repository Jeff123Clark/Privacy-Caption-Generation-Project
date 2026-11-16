"""Low-memory pre-scan: which packages of a large APK call privacy-relevant APIs?

Reads the DEX files directly (no Androguard), so it runs on APKs too large to build a
full APG for (PayPal: 25 dex files, 256k classes). Use its output to choose
`python -m apg build ... --include <packages>`.

    python scripts/prescan_apk.py input/APK/PayPal_10.18.0_APKPure.apk --group com.paypal.oslo.feature
    python scripts/prescan_apk.py <apk> --json output/prescan.json

What counts as a hit (a call instruction in a class's bytecode whose target is):
  * a curated source API from cypher/ppg_build.cypher (P2), matched on class + name;
  * any method of a privacy-relevant framework class (location, telephony, accounts,
    contacts/content providers, Bluetooth, Wi-Fi, NFC, camera, clipboard, EditText input);
  * any method of a known financial / identity SDK bundled in the APK;
  * a Document Analysis Module source (formatted_sources.csv), matched on class + name;
  * a text-input field: framework fields (Compose TextField / TextFieldState, EditText ...)
    and the app's own input components (TextInput, PasswordInput, CodeInput ...);
  * a no-argument getter named after personal data (getEmail, getLastFourDigits ...), using
    the P2c keyword list in ppg_build.cypher.
--classes-out lists every class with a hit of any of these kinds, ready for
`apg build --include @FILE`.
Each candidate method is decoded instruction by instruction, so only real invoke
instructions count (a fast byte search picks which methods to decode).
"""

from __future__ import annotations

import argparse
import collections
import json
import re
import struct
import sys
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from apg.dexscan import INVOKE_OPS as _INVOKE_OPS, invoked_methods, uleb  # noqa: E402

# class prefix -> category for "any method of this class/package"
CLASS_TARGETS: dict[str, str] = {
    "android.location.": "location",
    "com.google.android.gms.location.": "location",
    "android.net.wifi.WifiManager": "location",
    "android.telephony.TelephonyManager": "identifier",
    "android.accounts.AccountManager": "identifier",
    "com.google.android.gms.ads.identifier.": "identifier",
    "android.provider.ContactsContract": "contacts",
    "android.content.ContentResolver": "content_provider",
    "android.bluetooth.": "bluetooth",
    "android.nfc.": "nfc_payment",
    "android.hardware.camera2.": "camera",
    "androidx.camera.": "camera",
    "android.content.ClipboardManager": "clipboard",
    "android.widget.EditText": "user_input",
    "android.text.TextWatcher": "user_input",
    "androidx.compose.material3.TextFieldKt": "user_input",
    "androidx.compose.material3.OutlinedTextFieldKt": "user_input",
    "androidx.compose.material.TextFieldKt": "user_input",
    "androidx.compose.material.OutlinedTextFieldKt": "user_input",
    "androidx.compose.foundation.text.BasicTextFieldKt": "user_input",
    "androidx.compose.foundation.text.input.TextFieldState": "user_input",
    "androidx.compose.ui.text.input.TextFieldValue": "user_input",
    "android.view.autofill.": "user_input",
    # Financial / identity SDKs bundled in PayPal
    "com.plaid.": "financial_sdk",
    "com.microblink.": "card_or_id_scan",
    "com.miteksystems.": "card_or_id_scan",
    "com.facetec.": "biometric_identity",
    "financial.atomic.": "financial_sdk",
    "com.visa.": "financial_sdk",
    "com.discover.": "financial_sdk",
    "com.payair.": "nfc_payment",
    "com.gemalto.mfs.": "nfc_payment",
    "com.zettle.": "financial_sdk",
    "com.izettle.": "financial_sdk",
    "com.ingo.": "financial_sdk",
    "com.mastercard.": "financial_sdk",
    "com.knotapi.": "financial_sdk",
    "com.braintreepayments.": "financial_sdk",
    "my.com.softspace.": "nfc_payment",
}

INVOKE_OPS = bytes(sorted(_INVOKE_OPS))


def curated_sources() -> set[tuple[str, str]]:
    """(class, method) pairs from the P2 list in ppg_build.cypher."""
    text = (HERE.parent / "cypher" / "ppg_build.cypher").read_text()
    return set(re.findall(r"\{c:'([^']+)', m:'([^']+)', cat:", text))


def document_analysis_sources() -> set[tuple[str, str]]:
    """(class, method) pairs from the Document Analysis Module (formatted_sources.csv, P2b)."""
    import csv
    path = HERE.parent.parent / "Document Analysis Module" / "output" / "formatted_sources.csv"
    if not path.exists():
        return set()
    with open(path, encoding="utf-8") as f:
        return {(r["Class Name"], r["Method Name"]) for r in csv.DictReader(f) if r["Category"] != "NO_CATEGORY"}


def personal_data_keywords() -> list[tuple[str, bool]]:
    """(keyword, whole-name-only) from the P2c list in ppg_build.cypher."""
    text = (HERE.parent / "cypher" / "ppg_build.cypher").read_text()
    out = []
    for _cat, _dt, kws in re.findall(r"\['(\w+)', '([^']+)', \[([^\]]+)\]\]", text):
        out += [(k.strip(" '"), len(k.strip(" '")) <= 4) for k in kws.split(",")]
    return out


# An app's own text-input components (design systems wrap the framework fields):
# TextInput, PasswordInput, CodeInput, PinInput, OtpInput, *TextField. Same pattern as P3g.
INPUT_COMPONENT = re.compile(r"^((Basic|Outlined)?TextField|\w*TextInput|PasswordInput|CodeInput|PinInput|OtpInput)(-\w+)?$")

# Classes whose getters are not the app's data (same list as P3f in ppg_build.cypher)
GETTER_SKIP = ("android.", "java.", "javax.", "dalvik.", "kotlin.", "kotlinx.", "androidx.",
               "com.google.android.material.", "org.json.")


def is_personal_getter(name: str, keywords: list[tuple[str, bool]]) -> bool:
    if not name.startswith("get") or len(name) <= 4:
        return False
    n = re.sub(r"[^a-z0-9]", "", name[3:].lower())
    return any(n == k or (not exact and n.endswith(k)) for k, exact in keywords)


def scan_dex(b: bytes, sources: set, hits: dict, doc_sources: set = frozenset(),
             keywords: list = ()) -> int:
    u32 = lambda off: struct.unpack_from("<I", b, off)[0]
    sids_off, tids_off = u32(0x3C), u32(0x44)
    protos_off = u32(0x4C)
    mids_size, mids_off = u32(0x58), u32(0x5C)
    cd_size, cd_off = u32(0x60), u32(0x64)

    def string(i: int) -> str:
        _, o = uleb(b, u32(sids_off + 4 * i))
        return b[o:b.index(0, o)].decode("utf-8", "replace")

    def type_name(i: int) -> str:
        t = string(u32(tids_off + 4 * i))
        return t[1:-1].replace("/", ".") if t.startswith("L") else t

    # Target method indices in this dex
    targets: dict[int, str] = {}
    type_cache: dict[int, str] = {}
    for i in range(mids_size):
        cidx, proto, nidx = struct.unpack_from("<HHI", b, mids_off + 8 * i)
        cls = type_cache.get(cidx) or type_cache.setdefault(cidx, type_name(cidx))
        cat = next((c for p, c in CLASS_TARGETS.items() if cls.startswith(p)), None)
        if cat is None:
            name = string(nidx)
            if (cls, name) in sources:
                cat = "curated_source"
            elif (cls, name) in doc_sources:
                cat = "document_analysis_source"
            elif not cls.startswith(GETTER_SKIP) and INPUT_COMPONENT.match(name):
                cat = "user_input"
            elif keywords and not cls.startswith(GETTER_SKIP) and is_personal_getter(name, keywords):
                # no-argument getter that does not return boolean / void
                _shorty, ret, params = struct.unpack_from("<III", b, protos_off + 12 * proto)
                if params == 0 and type_name(ret) not in ("Z", "V"):
                    cat = "personal_data_getter"
        if cat:
            targets[i] = cat
    if not targets:
        return 0

    # 4-byte pattern: invoke opcode, arg byte, method index (u16 LE)
    idx_alt = b"|".join(re.escape(struct.pack("<H", i)) for i in targets if i < 0x10000)
    pat = re.compile(b"[" + re.escape(INVOKE_OPS) + b"].(?:" + idx_alt + b")", re.DOTALL)

    n = 0
    for c in range(cd_size):
        base = cd_off + 32 * c
        cls_name = type_name(u32(base))
        data_off = u32(base + 24)
        if not data_off:
            continue
        o = data_off
        sf, o = uleb(b, o)
        inf, o = uleb(b, o)
        dm, o = uleb(b, o)
        vm, o = uleb(b, o)
        for _ in range(sf + inf):
            _, o = uleb(b, o)
            _, o = uleb(b, o)
        for count in (dm, vm):
            for _ in range(count):
                _, o = uleb(b, o)
                _, o = uleb(b, o)
                code_off, o = uleb(b, o)
                if not code_off:
                    continue
                insns_size = u32(code_off + 12)
                start = code_off + 16
                # Cheap byte filter first; decode the method only when it may match.
                if pat.search(b, start, start + 2 * insns_size) is None:
                    continue
                for idx in invoked_methods(b, start, insns_size):
                    if idx in targets:
                        hits[cls_name][targets[idx]] += 1
                        n += 1
    return n


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("apk")
    ap.add_argument("--group", default="", help="report per package one level below this prefix "
                    "(e.g. com.paypal.oslo.feature); default: first 4 package parts")
    ap.add_argument("--json", help="write per-class hits to this file")
    ap.add_argument("--classes-out", metavar="FILE",
                    help="write every class that calls a known sensitive source (any hit kind above) "
                         "to FILE, one per line, for `apg build --include @FILE`")
    ap.add_argument("--only", default="", metavar="PREFIX",
                    help="with --classes-out: keep only classes under this package (e.g. com.paypal)")
    args = ap.parse_args()

    sources = curated_sources()
    doc_sources = document_analysis_sources()
    keywords = personal_data_keywords()
    print(f"  sources: {len(sources)} curated, {len(doc_sources)} Document Analysis, "
          f"{len(keywords)} personal-data names", file=sys.stderr)
    hits: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    z = zipfile.ZipFile(args.apk)
    dexes = sorted(n for n in z.namelist() if re.fullmatch(r"classes\d*\.dex", n))
    for name in dexes:
        n = scan_dex(z.read(name), sources, hits, doc_sources, keywords)
        print(f"  {name}: {n} hits", file=sys.stderr)

    def group(cls: str) -> str:
        parts = cls.split(".")
        if args.group and cls.startswith(args.group + "."):
            return args.group + "." + cls[len(args.group) + 1:].split(".")[0]
        return ".".join(parts[:4])

    by_group: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    classes: dict[str, set] = collections.defaultdict(set)
    for cls, c in hits.items():
        by_group[group(cls)].update(c)
        classes[group(cls)].add(cls)
    rows = sorted(by_group.items(), key=lambda kv: -sum(kv[1].values()))
    print(f"{'package':60} {'classes':>7}  categories (call sites)")
    for g, c in rows:
        print(f"{g:60} {len(classes[g]):7}  " + ", ".join(f"{k}={v}" for k, v in c.most_common()))
    if args.json:
        Path(args.json).write_text(json.dumps({k: dict(v) for k, v in hits.items()}, indent=1))
        print(f"wrote {args.json}", file=sys.stderr)
    if args.classes_out:
        # Every hit kind is a known sensitive source: curated APIs, Document Analysis
        # sources, personal-data getters, and the privacy-relevant API families above
        # (location, telephony identifiers, contacts, camera, Bluetooth, NFC, SDKs ...).
        chosen = sorted(c for c, v in hits.items() if v
                        and (not args.only or c.startswith(args.only + ".")))
        Path(args.classes_out).write_text("\n".join(chosen) + "\n")
        print(f"wrote {len(chosen)} classes that read known sensitive sources to {args.classes_out}",
              file=sys.stderr)


if __name__ == "__main__":
    main()
