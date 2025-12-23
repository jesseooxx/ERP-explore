"""
提取縮放公式 - 從 0x0040AB38 渲染函數
關鍵代碼已找到！
"""

import pefile
from capstone import *
from capstone.x86 import *

EXE_PATH = r"C:\真桌面\Claude code\ERP explore\nrp_backup\nrp32.exe"

def deep_analyze_scaling_code():
    """深度分析縮放計算代碼"""

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

    # 關鍵函數地址（從上一步分析得出）
    render_func_va = 0x0040AB38

    print("=" * 70)
    print("座標縮放公式提取")
    print("=" * 70)
    print(f"\n分析函數 @ 0x{render_func_va:08X}")

    # 從函數開始往前 500 字節反彙編（找到函數序言）
    offset = render_func_va - code_base - 500
    instructions = list(md.disasm(code_data[offset:offset+3000], code_base + offset))

    # 找到縮放計算代碼
    print(f"\n關鍵縮放計算代碼:")
    print("-" * 70)

    scaling_operations = []

    for i, insn in enumerate(instructions):
        # 查找 imul + idiv 組合
        if insn.mnemonic == 'imul':
            # 檢查下一條是否是 idiv
            if i+1 < len(instructions):
                next_insn = instructions[i+1]

                if next_insn.mnemonic in ['idiv', 'div']:
                    # 找到縮放計算！
                    scaling_operations.append((insn, next_insn))

                    print(f"\n縮放計算 @ 0x{insn.address:08X}:")
                    print(f"  {insn.mnemonic:8s} {insn.op_str}")
                    print(f"  {next_insn.mnemonic:8s} {next_insn.op_str}")

                    # 嘗試追蹤被乘數和除數
                    # imul eax, [ebp-0x24]
                    # idiv [ebp-0x470]
                    # 結果: eax = eax * [ebp-0x24] / [ebp-0x470]

                    print(f"  → 公式: result = value * {insn.op_str.split(',')[1].strip()} / {next_insn.op_str}")

                    # 向前追蹤這些變量的賦值
                    multiplicand = insn.op_str.split(',')[1].strip() if ',' in insn.op_str else ""
                    divisor = next_insn.op_str.strip()

                    if multiplicand and multiplicand.startswith('dword ptr [ebp'):
                        print(f"\n  追蹤 {multiplicand}:")
                        trace_stack_var(instructions, i, multiplicand)

                    if divisor.startswith('dword ptr [ebp'):
                        print(f"\n  追蹤 {divisor}:")
                        trace_stack_var(instructions, i, divisor)

    print(f"\n找到 {len(scaling_operations)} 個縮放計算")

    # 總結推測的公式
    print("\n" + "=" * 70)
    print("推測的座標轉換公式")
    print("=" * 70)

    print("""
基於反彙編分析，座標轉換公式可能是:

    device_x = (template_x * viewport_width) / window_width
    device_y = (template_y * viewport_height) / window_height

其中:
    - template_x/y: 模板中的座標值
    - window_width/height: SetWindowExtEx 設置的邏輯窗口大小
    - viewport_width/height: SetViewportExtEx 設置的視口大小（設備座標）

需要找到這些參數的實際數值！
""")

    # 掃描函數中的常量賦值
    print("\n函數中的常量賦值:")
    print("-" * 70)

    for insn in instructions:
        if insn.mnemonic == 'mov':
            ops = insn.op_str.split(',')
            if len(ops) == 2:
                src = ops[1].strip()
                # 如果是大的立即數
                if src.startswith('0x'):
                    val = int(src, 16)
                    if 100 <= val <= 10000:
                        print(f"  0x{insn.address:08X}: {insn.mnemonic} {insn.op_str}  // {val}")
                elif src.isdigit():
                    val = int(src)
                    if 100 <= val <= 10000:
                        print(f"  0x{insn.address:08X}: {insn.mnemonic} {insn.op_str}  // {val}")

    pe.close()

def trace_stack_var(instructions, current_idx, var_name):
    """追蹤棧變量的賦值"""
    # 提取偏移
    # 例如: "dword ptr [ebp - 0x24]" -> "-0x24"
    import re
    offset_match = re.search(r'\[ebp\s*-\s*0x([0-9a-fA-F]+)\]', var_name)
    if not offset_match:
        return

    offset_str = offset_match.group(1)

    # 向前掃描，找到對此位置的賦值
    for i in range(current_idx-1, max(0, current_idx-50), -1):
        insn = instructions[i]
        if insn.mnemonic == 'mov':
            # 檢查目標是否匹配
            if f'- 0x{offset_str}' in insn.op_str:
                src = insn.op_str.split(',')[1].strip()
                print(f"    0x{insn.address:08X}: {insn.mnemonic} {insn.op_str}")

                # 如果是立即數
                if src.startswith('0x') or src.isdigit():
                    val = int(src, 0) if '0x' in src else int(src)
                    print(f"      → 值: {val}")
                    break


if __name__ == "__main__":
    deep_analyze_scaling_code()
