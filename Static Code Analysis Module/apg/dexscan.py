"""Low-memory DEX reader for the whole-app overview (level 1 of the two-level build).

Androguard keeps every instruction of every class in memory, which does not fit for very
large APKs (PayPal: 25 dex files, 256k classes). This module reads the DEX files directly
and keeps only what the overview needs:

  * every class defined in the APK: superclass, interfaces, access flags;
  * every method: name, descriptor, access flags, whether it has code;
  * every call: caller method -> referenced method (as written in the invoke instruction).

Names are interned to integer ids so the whole of PayPal fits in a few GB.
Method signatures use the same smali form as the APG (``Lpkg/C;->m(I)V``), so overview
methods and APG methods share uids in Neo4j.
"""

from __future__ import annotations

import re
import struct
import zipfile
from array import array
from dataclasses import dataclass, field

NO_INDEX = 0xFFFFFFFF
INVOKE_OPS = frozenset(list(range(0x6E, 0x73)) + list(range(0x74, 0x79)) + [0xFA, 0xFB])


def _widths() -> list[int]:
    """Dalvik instruction width in 16-bit code units, by opcode."""
    w = [1] * 256
    for op, n in {0x02: 2, 0x03: 3, 0x05: 2, 0x06: 3, 0x08: 2, 0x09: 3, 0x13: 2, 0x14: 3,
                  0x15: 2, 0x16: 2, 0x17: 3, 0x18: 5, 0x19: 2, 0x1A: 2, 0x1B: 3, 0x1C: 2,
                  0x1F: 2, 0x20: 2, 0x22: 2, 0x23: 2, 0x24: 3, 0x25: 3, 0x26: 3, 0x29: 2,
                  0x2A: 3, 0x2B: 3, 0x2C: 3, 0xFA: 4, 0xFB: 4, 0xFC: 3, 0xFD: 3, 0xFE: 2,
                  0xFF: 2}.items():
        w[op] = n
    for lo, hi, n in ((0x2D, 0x3D, 2), (0x44, 0x6D, 2), (0x6E, 0x72, 3), (0x74, 0x78, 3),
                      (0x90, 0xAF, 2), (0xD0, 0xE2, 2)):
        for op in range(lo, hi + 1):
            w[op] = n
    return w


WIDTH = _widths()


def invoked_methods(b: bytes, start: int, units: int):
    """Yield the method index of every invoke instruction in one method's code."""
    i = 0
    while i < units:
        o = start + 2 * i
        op, hi = b[o], b[o + 1]
        if op == 0x00 and hi in (1, 2, 3):          # switch / array payloads
            if hi == 1:
                i += struct.unpack_from("<H", b, o + 2)[0] * 2 + 4
            elif hi == 2:
                i += struct.unpack_from("<H", b, o + 2)[0] * 4 + 2
            else:
                width, size = struct.unpack_from("<HI", b, o + 2)
                i += (size * width + 1) // 2 + 4
            continue
        if op in INVOKE_OPS:
            yield struct.unpack_from("<H", b, o + 2)[0]
        i += WIDTH[op]


def uleb(b: bytes, o: int) -> tuple[int, int]:
    r = s = 0
    while True:
        x = b[o]
        o += 1
        r |= (x & 0x7F) << s
        s += 7
        if x < 0x80:
            return r, o


def dex_names(apk_path) -> list[str]:
    with zipfile.ZipFile(apk_path) as z:
        return sorted((n for n in z.namelist() if re.fullmatch(r"classes\d*\.dex", n)),
                      key=lambda n: int(n[7:-4] or 1))


@dataclass
class Overview:
    """Whole-app classes, methods and calls, with interned names."""
    names: list[str] = field(default_factory=list)          # id -> string
    _ids: dict[str, int] = field(default_factory=dict)
    # dalvik class name id -> (superclass id or -1, [interface ids], access flags)
    classes: dict[int, tuple[int, tuple[int, ...], int]] = field(default_factory=dict)
    # method id -> (class id, name+descriptor id); a method id is the id of its signature
    method_cls: dict[int, int] = field(default_factory=dict)
    method_flags: dict[int, int] = field(default_factory=dict)   # only methods defined in the APK
    calls_from: array = field(default_factory=lambda: array("I"))  # caller method ids
    calls_to: array = field(default_factory=lambda: array("I"))    # callee method ids
    code_units: dict[int, int] = field(default_factory=dict)     # class id -> 16-bit code units

    def intern(self, s: str) -> int:
        i = self._ids.get(s)
        if i is None:
            i = self._ids[s] = len(self.names)
            self.names.append(s)
        return i

    def name(self, i: int) -> str:
        return self.names[i]

    def method(self, cls: str, key: str) -> int:
        mid = self.intern(f"{cls}->{key}")
        if mid not in self.method_cls:
            self.method_cls[mid] = self.intern(cls)
        return mid

    @property
    def n_calls(self) -> int:
        return len(self.calls_from)


def read_overview(apk_path) -> Overview:
    ov = Overview()
    with zipfile.ZipFile(apk_path) as z:
        for name in dex_names(apk_path):
            _read_dex(z.read(name), ov)
    return ov


def _read_dex(b: bytes, ov: Overview) -> None:
    u32 = lambda off: struct.unpack_from("<I", b, off)[0]
    sids_off, tids_off = u32(0x3C), u32(0x44)
    protos_off = u32(0x4C)
    mids_size, mids_off = u32(0x58), u32(0x5C)
    cd_size, cd_off = u32(0x60), u32(0x64)

    strings: dict[int, str] = {}

    def string(i: int) -> str:
        s = strings.get(i)
        if s is None:
            _, o = uleb(b, u32(sids_off + 4 * i))
            s = strings[i] = b[o:b.index(0, o)].decode("utf-8", "replace")
        return s

    def type_desc(i: int) -> str:
        return string(u32(tids_off + 4 * i))

    protos: dict[int, str] = {}

    def proto(i: int) -> str:
        p = protos.get(i)
        if p is None:
            _shorty, ret, params_off = struct.unpack_from("<III", b, protos_off + 12 * i)
            params = ""
            if params_off:
                n = u32(params_off)
                params = "".join(type_desc(struct.unpack_from("<H", b, params_off + 4 + 2 * k)[0])
                                 for k in range(n))
            p = protos[i] = f"({params}){type_desc(ret)}"
        return p

    # Global method id for each method index of this dex, computed on first use.
    mid_cache: dict[int, int] = {}

    def method_id(idx: int) -> int:
        m = mid_cache.get(idx)
        if m is None:
            cidx, pidx, nidx = struct.unpack_from("<HHI", b, mids_off + 8 * idx)
            m = mid_cache[idx] = ov.method(type_desc(cidx), string(nidx) + proto(pidx))
        return m

    calls_from, calls_to = ov.calls_from, ov.calls_to
    for c in range(cd_size):
        base = cd_off + 32 * c
        cls_idx, flags, super_idx, itf_off = struct.unpack_from("<IIII", b, base)
        cls = type_desc(cls_idx)
        cid = ov.intern(cls)
        if cid in ov.classes:
            continue                                  # duplicate definition: first one wins (as ART)
        sup = ov.intern(type_desc(super_idx)) if super_idx != NO_INDEX else -1
        itfs: tuple[int, ...] = ()
        if itf_off:
            n = u32(itf_off)
            itfs = tuple(ov.intern(type_desc(struct.unpack_from("<H", b, itf_off + 4 + 2 * k)[0]))
                         for k in range(n))
        ov.classes[cid] = (sup, itfs, flags)
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
            idx = 0
            for _ in range(count):
                diff, o = uleb(b, o)
                mflags, o = uleb(b, o)
                code_off, o = uleb(b, o)
                idx += diff
                mid = method_id(idx)
                ov.method_flags[mid] = mflags
                if not code_off:
                    continue
                insns_size = u32(code_off + 12)
                ov.code_units[cid] = ov.code_units.get(cid, 0) + insns_size
                for t in invoked_methods(b, code_off + 16, insns_size):
                    calls_from.append(mid)
                    calls_to.append(method_id(t))
