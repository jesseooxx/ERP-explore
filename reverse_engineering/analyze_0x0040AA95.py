"""
直接分析關鍵座標計算代碼 @ 0x0040AA95
之前發現的 imul/idiv 操作
"""

import pefile
from capstone import *
from capstone.x86 import *

EXE_PATH = r"C:\真桌面\Claude code\ERP explore\nrp_backup\nrp32.exe"

def analyze_key_code():
    """分析關鍵代碼區域"""

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

    # 關鍵地址（從之前分析發現）
    key_address = 0x0040AA95

    print("=" * 70)
    print(f"分析關鍵座標計算代碼 @ 0x{key_address:08X}")
    print("=" * 70)

    # 反彙編這個區域（前後各 200 字節）
    offset = key_address - code_base - 200
    instructions = list(md.disasm(code_data[offset:offset+1000], code_base + offset))

    # 找到目標指令
    target_idx = None
    for i, insn in enumerate(instructions):
        if insn.address == key_address:
            target_idx = i
            break

    if target_idx is None:
        print("找不到目標地址")
        return

    print(f"\n完整代碼序列 (前後 30 條指令):")
    print("-" * 70)

    start_idx = max(0, target_idx - 30)
    end_idx = min(len(instructions), target_idx + 30)

    for i in range(start_idx, end_idx):
        insn = instructions[i]
        marker = " >>>" if i == target_idx else "    "

        # 高亮關鍵操作
        if insn.mnemonic in ['imul', 'idiv', 'div', 'mul']:
            marker = " ***"

        print(f"{marker} 0x{insn.address:08X}: {insn.mnemonic:8s} {insn.op_str}")

    # 專門提取 imul/idiv 模式
    print(f"\n" + "=" * 70)
    print("座標縮放計算模式")
    print("=" * 70)

    for i in range(start_idx, end_idx):
        insn = instructions[i]

        if insn.mnemonic in ['imul', 'mul']:
            # 下一條可能是 idiv
            if i+1 < len(instructions):
                next_insn = instructions[i+1]

                if next_insn.mnemonic in ['idiv', 'div']:
                    print(f"\n縮放模式 @ 0x{insn.address:08X}:")
                    print(f"  0x{insn.address:08X}: {insn.mnemonic:8s} {insn.op_str}")
                    print(f"  0x{next_insn.address:08X}: {next_insn.mnemonic:8s} {next_insn.op_str}")
                    print(f"  → eax = eax * {insn.op_str.split(',')[1] if ',' in insn.op_str else insn.op_str} / {next_insn.op_str}")

    # 追蹤關鍵變量
    print(f"\n" + "=" * 70)
    print("關鍵變量追蹤")
    print("=" * 70)

    # 向前掃描查找常量賦值
    print(f"\n棧變量賦值:")
    for i in range(target_idx - 50, target_idx):
        if i < 0:
            continue
        insn = instructions[i]

        if insn.mnemonic == 'mov':
            # 查找賦值到 [ebp-XXX]
            if 'ebp -' in insn.op_str:
                ops = insn.op_str.split(',')
                if len(ops) == 2:
                    src = ops[1].strip()

                    # 如果是立即數或全局變量
                    if src.startswith('0x') or src.isdigit() or src.startswith('dword ptr [0x'):
                        print(f"  0x{insn.address:08X}: {insn.mnemonic} {insn.op_str}")

                        # 如果是立即數，計算值
                        if src.startswith('0x'):
                            val = int(src, 16)
                            if 10 <= val <= 10000:
                                print(f"      → 值: {val} (0x{val:X})")
                        elif src.isdigit():
                            val = int(src)
                            if 10 <= val <= 10000:
                                print(f"      → 值: {val}")

    pe.close()


if __name__ == "__main__":
    analyze_key_code()
