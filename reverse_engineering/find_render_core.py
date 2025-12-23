"""
精確定位核心渲染函數
尋找包含完整渲染序列的函數: SetMapMode -> SetWindowExtEx -> TextOut
"""

import pefile
from capstone import *
from capstone.x86 import *
from collections import defaultdict

EXE_PATH = r"C:\真桌面\Claude code\ERP explore\nrp_backup\nrp32.exe"

def find_rendering_pipeline():
    """找到完整的渲染管線"""

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
    import_map = {}
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    import_map[imp.address] = imp.name.decode('utf-8', errors='ignore')

    print("=" * 70)
    print("尋找渲染管線函數")
    print("=" * 70)

    # 反彙編所有指令
    instructions = list(md.disasm(code_data, code_base))

    # 記錄每個 GDI 調用的位置
    gdi_calls_by_address = {}
    for insn in instructions:
        if insn.mnemonic == 'call':
            target = None
            if len(insn.operands) > 0:
                op = insn.operands[0]
                if op.type == X86_OP_MEM:
                    target = op.mem.disp

            if target and target in import_map:
                func_name = import_map[target]
                gdi_calls_by_address[insn.address] = func_name

    print(f"\n找到 {len(gdi_calls_by_address)} 個 API 調用")

    # 找到包含渲染序列的區域
    render_signature = ['SetMapMode', 'SetWindowExtEx', 'SetViewportExtEx']

    print(f"\n尋找渲染簽名序列: {' -> '.join(render_signature)}")

    matches = []
    addresses = sorted(gdi_calls_by_address.keys())

    for i, addr in enumerate(addresses):
        func = gdi_calls_by_address[addr]

        if func == render_signature[0]:  # SetMapMode
            # 檢查後續是否有完整序列
            found_sequence = [addr]
            sig_idx = 1

            for j in range(i+1, min(i+20, len(addresses))):
                next_addr = addresses[j]
                next_func = gdi_calls_by_address[next_addr]

                if sig_idx < len(render_signature) and next_func == render_signature[sig_idx]:
                    found_sequence.append(next_addr)
                    sig_idx += 1

                    if sig_idx == len(render_signature):
                        # 找到完整序列！
                        matches.append(found_sequence)
                        print(f"\n找到匹配 @ 0x{addr:08X} - 0x{next_addr:08X}")
                        break

    # 詳細分析每個匹配
    for match_idx, match_addrs in enumerate(matches):
        print(f"\n{'='*70}")
        print(f"匹配 #{match_idx+1}: 渲染管線 @ 0x{match_addrs[0]:08X}")
        print(f"{'='*70}")

        # 獲取整個函數範圍（從第一個調用往前找函數序言）
        func_start = match_addrs[0] - 200  # 向前查找
        func_end = match_addrs[-1] + 500

        # 提取這段代碼
        func_instructions = []
        for insn in instructions:
            if func_start <= insn.address <= func_end:
                func_instructions.append(insn)

        # 完整反彙編此函數
        print(f"\n完整反彙編 ({len(func_instructions)} 條指令):")
        print("-" * 70)

        for insn in func_instructions[:100]:  # 顯示前 100 條
            # 檢查是否是 GDI 調用
            is_gdi_call = insn.address in gdi_calls_by_address

            if is_gdi_call:
                func_name = gdi_calls_by_address[insn.address]
                print(f">>> 0x{insn.address:08X}: CALL {func_name}")
            else:
                # 高亮關鍵指令
                if insn.mnemonic in ['push', 'mov', 'imul', 'idiv', 'add', 'sub']:
                    print(f"    0x{insn.address:08X}: {insn.mnemonic:8s} {insn.op_str}")

        if len(func_instructions) > 100:
            print(f"\n... 還有 {len(func_instructions) - 100} 條指令")

        # 專門提取 SetWindowExtEx 和 SetViewportExtEx 的參數
        print(f"\n座標設置分析:")
        print("-" * 70)

        for i, addr in enumerate(match_addrs):
            func = gdi_calls_by_address[addr]
            print(f"\n{func} @ 0x{addr:08X}:")

            # 找前面的 push 指令
            insn_idx = next(idx for idx, insn in enumerate(func_instructions) if insn.address == addr)

            pushes = []
            for j in range(insn_idx-1, max(0, insn_idx-10), -1):
                if func_instructions[j].mnemonic == 'push':
                    pushes.append(func_instructions[j])
                elif func_instructions[j].mnemonic in ['call']:
                    break

            pushes.reverse()

            print(f"  參數 (共 {len(pushes)} 個):")
            for idx, push in enumerate(pushes):
                print(f"    [{idx}] 0x{push.address:08X}: push {push.op_str}")

                # 如果是寄存器，追蹤值
                if push.op_str in ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi']:
                    # 簡單追蹤：找最近的 mov
                    push_idx = next(idx for idx, insn in enumerate(func_instructions) if insn.address == push.address)
                    for k in range(push_idx-1, max(0, push_idx-10), -1):
                        prev = func_instructions[k]
                        if prev.mnemonic == 'mov':
                            ops = prev.op_str.split(',')
                            if len(ops) == 2 and ops[0].strip() == push.op_str:
                                print(f"        來自: 0x{prev.address:08X}: {prev.mnemonic} {prev.op_str}")
                                break

    pe.close()


if __name__ == "__main__":
    find_rendering_pipeline()
