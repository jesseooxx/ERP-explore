"""
在 nrp32.exe 中搜索座標相關常量
"""

import pefile
import struct

EXE_PATH = r"C:\真桌面\Claude code\ERP explore\nrp_backup\nrp32.exe"

def find_constants_in_exe():
    """搜索可能的座標常量"""

    pe = pefile.PE(EXE_PATH)

    print("=" * 70)
    print("搜索座標相關常量")
    print("=" * 70)

    # 可能的常量值
    search_values = [
        900,    # 模板 page_width
        1200,   # 模板 page_height
        595,    # A4 width in points
        842,    # A4 height in points
        210,    # A4 width in mm
        297,    # A4 height in mm
        72,     # DPI
        254,    # mm to inch (25.4 * 10)
        283,    # 我們之前用的 0.283
        100,    # 可能的縮放因子
        1000,   # 可能的縮放因子
        10000,  # 可能的縮放因子
    ]

    print("\n搜索常量值...")

    # 獲取所有段
    all_data = pe.get_memory_mapped_image()

    for value in search_values:
        print(f"\n查找 {value}:")

        # 以 DWORD (little-endian) 搜索
        value_bytes = struct.pack('<I', value)
        offset = 0
        found_count = 0

        while offset < len(all_data) - 4:
            pos = all_data.find(value_bytes, offset)
            if pos == -1:
                break

            # 找到匹配
            # 確定在哪個段
            section_name = "unknown"
            rva = pos
            for section in pe.sections:
                if section.VirtualAddress <= rva < section.VirtualAddress + section.Misc_VirtualSize:
                    section_name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
                    break

            va = pe.OPTIONAL_HEADER.ImageBase + rva
            print(f"  @ RVA 0x{rva:08X} (VA 0x{va:08X}) in {section_name}")

            found_count += 1
            if found_count >= 5:  # 限制輸出
                print(f"  ... (更多)")
                break

            offset = pos + 1

    # 也搜索浮點數
    print("\n" + "=" * 70)
    print("搜索可能的縮放因子（浮點數）")
    print("=" * 70)

    float_values = [
        0.1,        # 0.1mm
        0.01,       # 0.01mm
        0.283,      # 我們用的
        0.661,      # 595/900
        0.702,      # 842/1200
        72.0 / 25.4,  # points per mm
        25.4,       # mm per inch
        72.0,       # points per inch
    ]

    for value in float_values:
        value_bytes = struct.pack('<f', value)
        pos = all_data.find(value_bytes)
        if pos != -1:
            va = pe.OPTIONAL_HEADER.ImageBase + pos
            print(f"  {value:.6f} @ 0x{va:08X}")

    pe.close()


def analyze_getdevicecaps_usage():
    """分析 GetDeviceCaps 調用 - 獲取設備分辨率"""

    pe = pefile.PE(EXE_PATH)
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
    imports = {}
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    imports[imp.address] = imp.name.decode('utf-8', errors='ignore')

    print("\n" + "=" * 70)
    print("GetDeviceCaps 調用分析（獲取 DPI/分辨率）")
    print("=" * 70)

    print("\nGetDeviceCaps 參數常量:")
    print("  HORZSIZE = 4    (寬度, mm)")
    print("  VERTSIZE = 6    (高度, mm)")
    print("  HORZRES = 8     (寬度, pixels)")
    print("  VERTRES = 10    (高度, pixels)")
    print("  LOGPIXELSX = 88 (水平 DPI)")
    print("  LOGPIXELSY = 90 (垂直 DPI)")

    instructions = list(md.disasm(code_data, code_base))

    for i, insn in enumerate(instructions):
        if insn.mnemonic != 'call':
            continue

        target = None
        if len(insn.operands) > 0:
            op = insn.operands[0]
            if op.type == X86_OP_MEM:
                target = op.mem.disp

        if target and target in imports and imports[target] == 'GetDeviceCaps':
            # 找前面的 push（第二個參數是 index）
            for j in range(i-1, max(0, i-5), -1):
                prev = instructions[j]
                if prev.mnemonic == 'push':
                    param = prev.op_str
                    # 檢查是否是立即數
                    if param.isdigit():
                        index = int(param)
                        index_names = {
                            4: "HORZSIZE",
                            6: "VERTSIZE",
                            8: "HORZRES",
                            10: "VERTRES",
                            88: "LOGPIXELSX",
                            90: "LOGPIXELSY"
                        }
                        index_name = index_names.get(index, f"Index {index}")
                        print(f"  @ 0x{insn.address:08X}: GetDeviceCaps({index_name})")
                    break

    pe.close()


if __name__ == "__main__":
    find_constants_in_exe()
    analyze_getdevicecaps_usage()
