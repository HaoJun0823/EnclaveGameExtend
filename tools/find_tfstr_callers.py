#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""枚举 GameWorld.dll 中全部 call 0x10054F00（TFStr<252> 构造）的调用点，
   打印 call 指令 RVA 与真实返回地址 RVA，并标注是否落在字幕区 [0x8D000,0x8F000]。
   目的：核对 v16 hook1 调用者白名单（0x8DD09/0x8DD31/0x8E362/0x8DDE3）是否
   把它们当成【返回地址】来比对 —— 若白名单是 call 指令地址，则返回地址 = call+5，
   永远对不上 → 全部 fallback 窄构造 → 攀被截断。
"""
import sys, struct

try:
    sys.stdout.reconfigure(errors="replace")
    sys.stderr.reconfigure(errors="replace")
except Exception:
    pass

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_GRP_CALL, CS_OP_IMM
except ImportError:
    sys.path.insert(0, r"C:\Users\haojun0823\.workbuddy\binaries\python\envs\default\Lib\site-packages")
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_GRP_CALL, CS_OP_IMM

DLL = r"I:\SteamLibrary\steamapps\common\Enclave\汉化乱码工程\GameWorld_live2.dll"
TARGET = 0x10054F00
SUB_LO, SUB_HI = 0x8D000, 0x8F000

def main():
    res_path = r"G:\Projects\EnclaveGameExtend\tools\_tfstr_result.txt"
    sys.stdout = open(res_path, "w", encoding="utf-8")
    data = open(DLL, "rb").read()
    # DOS
    assert data[:2] == b"MZ"
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    # NT: Signature(4) + FileHeader(20) + OptionalHeader
    # FileHeader @ e_lfanew+4: Machine(0) NumberOfSections(2) TimeDateStamp(4)
    #   PointerToSymbolTable(8) NumberOfSymbols(12) SizeOfOptionalHeader(16) Characteristics(18)
    # OptionalHeader @ e_lfanew+4+20
    num_sect = struct.unpack_from("<H", data, e_lfanew + 4 + 2)[0]
    size_opt = struct.unpack_from("<H", data, e_lfanew + 4 + 16)[0]  # FileHeader.SizeOfOptionalHeader
    oh_off = e_lfanew + 4 + 20
    magic = struct.unpack_from("<H", data, oh_off)[0]
    is_pe32 = (magic == 0x10B)
    if is_pe32:
        image_base = struct.unpack_from("<I", data, oh_off + 28)[0]
    else:
        image_base = struct.unpack_from("<Q", data, oh_off + 24)[0]
    sect_off = oh_off + size_opt
    sections = []
    for i in range(num_sect):
        base = sect_off + i * 40
        name = data[base:base+8].split(b"\x00")[0].decode("latin1", "replace")
        vsize = struct.unpack_from("<I", data, base + 8)[0]
        vaddr = struct.unpack_from("<I", data, base + 12)[0]
        rsize = struct.unpack_from("<I", data, base + 16)[0]
        roff = struct.unpack_from("<I", data, base + 20)[0]
        flags = struct.unpack_from("<I", data, base + 36)[0]
        sections.append((name, vaddr, vsize, roff, rsize, flags))

    def va_to_off(va):
        for (name, vaddr, vsize, roff, rsize, flags) in sections:
            if vaddr <= (va - image_base) < vaddr + vsize:
                return roff + ((va - image_base) - vaddr)
        return None

    # 收集所有【可执行】节的原始字节，建立 (file_off, va) 映射
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    hits = []
    total_calls = 0
    from collections import Counter
    call_targets = Counter()
    print(f"image_base = {image_base:08X}")
    for (name, vaddr, vsize, roff, rsize, flags) in sections:
        flagstr = ("CODE" if flags & 0x20 else "") + (" EXEC" if flags & 0x200000 else "")
        print(f"  sect {name:<8} va={vaddr:08X} vsize={vsize:08X} roff={roff:08X} rsize={rsize:08X} {flagstr}")
        # IMAGE_SCN_CNT_CODE = 0x20 ; IMAGE_SCN_MEM_EXECUTE = 0x200000
        if not (flags & 0x20) and not (flags & 0x200000):
            continue
        seg = data[roff:roff+rsize]
        base_va = image_base + vaddr
        for insn in md.disasm(seg, base_va):
            if CS_GRP_CALL in insn.groups:
                total_calls += 1
                for op in insn.operands:
                    if op.type == CS_OP_IMM:
                        call_targets[op.imm - image_base] += 1
            # 任何操作数 == TARGET（覆盖 E8 rel32 / mov reg,imm / call reg 前置加载 等）
            for op in insn.operands:
                if op.type == CS_OP_IMM and op.imm == TARGET:
                    call_rva = insn.address - image_base
                    is_call = CS_GRP_CALL in insn.groups
                    print(f"  REF  0x{call_rva:08X}  {insn.mnemonic} {insn.op_str}  ({'CALL' if is_call else 'non-call'})")
                    if is_call:
                        ret_rva = (insn.address + insn.size) - image_base
                        in_sub = SUB_LO <= ret_rva < SUB_HI
                        hits.append((call_rva, ret_rva, insn.size, name, in_sub))
    print(f"total CALL instructions scanned = {total_calls}")
    print("top 20 call targets (RVA):")
    for rva, cnt in call_targets.most_common(20):
        print(f"  0x{rva:08X}  x{cnt}")
    hits.sort()
    print(f"call 0x{TARGET:X} 共 {len(hits)} 处：")
    print(f"{'callRVA':>8} {'retRVA':>8} {'len':>3}  sect   in_subtitle")
    for call_rva, ret_rva, sz, name, in_sub in hits:
        mark = "  <== 字幕区" if in_sub else ""
        print(f"{call_rva:08X} {ret_rva:08X} {sz:3d}  {name:<8} {in_sub}{mark}")
    # 单独列出字幕区的返回地址（hook1 真实该匹配的）
    sub_rets = sorted({ret for (_, ret, _, _, insub) in hits if insub})
    print("\n字幕区返回地址集合（hook1 应匹配这些）：")
    print("  " + ", ".join(f"0x{r:08X}" for r in sub_rets))
    # 白名单比对
    wl = [0x8DD09, 0x8DD31, 0x8E362, 0x8DDE3]
    print("\n当前白名单（当作返回地址比对）：")
    for w in wl:
        ok = any(w == ret for (_, ret, _, _, _) in hits)
        print(f"  0x{w:08X}  {'命中某返回地址' if ok else '未命中任何返回地址!'}")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("ERROR:", repr(e))
        import traceback
        traceback.print_exc()
