"""
終極分析 - 手動反編譯關鍵渲染函數
完全重建 nrp32.exe 的渲染邏輯
"""

import pefile
from capstone import *
from capstone.x86 import *
import struct

EXE_PATH = r"C:\真桌面\Claude code\ERP explore\nrp_backup\nrp32.exe"

def manual_decompile_function(pe, start_va: int, func_name: str):
    """手動反編譯函數"""

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True

    code_section = None
    for section in pe.sections:
        if section.Name.decode('utf-8', errors='ignore').rstrip('\x00') == '.text':
            code_section = section
            break

    code_data = code_section.get_data()
    code_base = pe.OPTIONAL_HEADER.ImageBase + code_section.VirtualAddress

    offset = start_va - code_base
    if offset < 0 or offset >= len(code_data):
        return

    print(f"\n{'='*70}")
    print(f"手動反編譯: {func_name} @ 0x{start_va:08X}")
    print(f"{'='*70}\n")

    # 反彙編前 200 條指令
    instructions = []
    for insn in md.disasm(code_data[offset:offset+2000], start_va):
        instructions.append(insn)
        if len(instructions) >= 200:
            break

    # 重建高級邏輯
    print("彙編代碼分析:\n")

    variables = {}  # 追蹤局部變量
    gdi_calls = []

    for i, insn in enumerate(instructions):
        addr_str = f"0x{insn.address:08X}"

        # 識別關鍵操作
        if insn.mnemonic == 'mov':
            # 追蹤賦值
            ops = insn.op_str.split(',')
            if len(ops) == 2:
                dest = ops[0].strip()
                src = ops[1].strip()

                # 如果是立即數賦值，記錄
                if src.startswith('0x') or (src.isdigit() and int(src) > 10):
                    variables[dest] = src
                    print(f"{addr_str}: {dest} = {src}  // 賦值常量")

        elif insn.mnemonic == 'imul':
            # 乘法運算 - 可能是座標縮放
            print(f"{addr_str}: {insn.mnemonic} {insn.op_str}  // 乘法（座標縮放？）")

        elif insn.mnemonic == 'idiv' or insn.mnemonic == 'div':
            # 除法運算
            print(f"{addr_str}: {insn.mnemonic} {insn.op_str}  // 除法")

        elif insn.mnemonic == 'call':
            # 函數調用
            # 檢查是否是 import
            if len(insn.operands) > 0:
                op = insn.operands[0]
                if op.type == X86_OP_MEM:
                    target = op.mem.disp
                    # 查看是否在導入表
                    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                        for entry in pe.DIRECTORY_ENTRY_IMPORT:
                            for imp in entry.imports:
                                if imp.address == target and imp.name:
                                    func = imp.name.decode('utf-8', errors='ignore')
                                    gdi_calls.append((insn.address, func))
                                    print(f"{addr_str}: CALL {func}")
                                    break

        elif insn.mnemonic == 'ret' or insn.mnemonic == 'retn':
            print(f"{addr_str}: {insn.mnemonic}  // 函數返回")
            break

    # 總結 GDI 調用序列
    print(f"\n{'='*70}")
    print(f"GDI 調用序列:")
    print(f"{'='*70}\n")
    for addr, func in gdi_calls:
        print(f"  0x{addr:08X}: {func}")


def find_and_analyze_render_function():
    """找到並分析主渲染函數"""

    pe = pefile.PE(EXE_PATH)

    print("=" * 70)
    print("尋找主渲染函數")
    print("=" * 70)

    # 策略：找到包含大量 GDI 調用的函數
    # 特徵：SaveDC -> SetMapMode -> SetWindowExtEx -> ... -> TextOut -> ... -> RestoreDC

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True

    code_section = None
    for section in pe.sections:
        if section.Name.decode('utf-8', errors='ignore').rstrip('\x00') == '.text':
            code_section = section
            break

    code_data = code_section.get_data()
    code_base = pe.OPTIONAL_HEADER.ImageBase + code_section.VirtualAddress

    # 導入表
    gdi_imports = {}
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode('utf-8', errors='ignore')
            if 'GDI32' in dll or 'USER32' in dll:
                for imp in entry.imports:
                    if imp.name:
                        gdi_imports[imp.address] = imp.name.decode('utf-8', errors='ignore')

    print(f"\n找到 {len(gdi_imports)} 個 GDI/USER32 函數")

    # 反彙編並找call密集區域
    instructions = list(md.disasm(code_data, code_base))

    # 統計每個 1000 字節區塊的 GDI 調用數
    block_size = 1000
    gdi_density = {}

    for insn in instructions:
        if insn.mnemonic == 'call':
            target = None
            if len(insn.operands) > 0:
                op = insn.operands[0]
                if op.type == X86_OP_MEM:
                    target = op.mem.disp

            if target and target in gdi_imports:
                block = (insn.address - code_base) // block_size
                gdi_density[block] = gdi_density.get(block, 0) + 1

    # 找到 GDI 調用最密集的區塊
    top_blocks = sorted(gdi_density.items(), key=lambda x: -x[1])[:5]

    print(f"\nGDI 調用最密集的代碼區塊:")
    for block, count in top_blocks:
        start_va = code_base + (block * block_size)
        print(f"  0x{start_va:08X} - 0x{start_va+block_size:08X}: {count} 個調用")

    # 深度分析第一個最密集區塊
    if top_blocks:
        top_block = top_blocks[0][0]
        start_va = code_base + (top_block * block_size)

        print(f"\n深度分析最密集區塊 @ 0x{start_va:08X}")
        manual_decompile_function(pe, start_va, "Suspected Render Function")

    pe.close()


if __name__ == "__main__":
    find_and_analyze_render_function()
