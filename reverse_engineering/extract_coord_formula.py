"""
提取真實座標轉換公式
通過分析 SetWindowExtEx 和 SetViewportExtEx 調用
"""

import pefile
from capstone import *
from capstone.x86 import *

EXE_PATH = r"C:\真桌面\Claude code\ERP explore\nrp_backup\nrp32.exe"

def analyze_coordinate_setup():
    """分析座標系統設置"""

    pe = pefile.PE(EXE_PATH)
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True

    # 獲取代碼段
    code_section = None
    for section in pe.sections:
        if section.Name.decode('utf-8', errors='ignore').rstrip('\x00') == '.text':
            code_section = section
            break

    code_data = code_section.get_data()
    code_base = pe.OPTIONAL_HEADER.ImageBase + code_section.VirtualAddress

    # 構建導入表
    imports = {}
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    imports[imp.address] = imp.name.decode('utf-8', errors='ignore')

    print("=" * 70)
    print("座標系統設置分析")
    print("=" * 70)

    # 關鍵函數
    target_functions = [
        'SetMapMode',
        'SetWindowExtEx',
        'SetViewportExtEx',
        'SetWindowOrgEx',
        'SetViewportOrgEx'
    ]

    # 找到所有調用
    all_calls = {func: [] for func in target_functions}

    instructions = list(md.disasm(code_data, code_base))

    for i, insn in enumerate(instructions):
        if insn.mnemonic != 'call':
            continue

        # 獲取目標
        target = None
        if len(insn.operands) > 0:
            op = insn.operands[0]
            if op.type == X86_OP_IMM:
                target = op.imm
            elif op.type == X86_OP_MEM:
                target = op.mem.disp

        if target and target in imports:
            func_name = imports[target]
            if func_name in target_functions:
                # 提取前面的 push 指令（參數）
                params = []
                for j in range(i-1, max(0, i-10), -1):
                    prev = instructions[j]
                    if prev.mnemonic == 'push':
                        params.append(prev.op_str)
                    elif prev.mnemonic in ['call', 'ret']:
                        break

                params.reverse()
                all_calls[func_name].append({
                    'addr': insn.address,
                    'params': params
                })

    # 顯示結果
    print("\n找到的座標設置調用:")
    print("-" * 70)

    for func, calls in all_calls.items():
        if not calls:
            continue

        print(f"\n{func}: {len(calls)} 次調用")

        for idx, call in enumerate(calls):
            print(f"  調用 #{idx+1} @ 0x{call['addr']:08X}")
            print(f"    參數: {call['params']}")

            # 解釋參數
            if func == 'SetMapMode':
                if call['params']:
                    mode_str = call['params'][0]
                    if '8' in mode_str:
                        print(f"      → MM_ANISOTROPIC (自定義映射)")

            elif func == 'SetWindowExtEx':
                print(f"      → 設置邏輯窗口範圍 (模板座標)")
                if len(call['params']) >= 3:
                    print(f"         寬度: {call['params'][1]}")
                    print(f"         高度: {call['params'][2]}")

            elif func == 'SetViewportExtEx':
                print(f"      → 設置視口範圍 (設備座標/像素)")
                if len(call['params']) >= 3:
                    print(f"         寬度: {call['params'][1]}")
                    print(f"         高度: {call['params'][2]}")

    # 分析成對的 SetWindowExtEx 和 SetViewportExtEx
    print("\n" + "=" * 70)
    print("座標轉換公式推導")
    print("=" * 70)

    window_calls = all_calls.get('SetWindowExtEx', [])
    viewport_calls = all_calls.get('SetViewportExtEx', [])

    if window_calls and viewport_calls:
        print("\n找到成對的設置:")
        # 找距離最近的配對
        for wcall in window_calls[:3]:
            waddr = wcall['addr']
            # 找最近的 viewport 調用
            closest = None
            min_dist = float('inf')
            for vcall in viewport_calls:
                dist = abs(vcall['addr'] - waddr)
                if dist < min_dist and dist < 200:  # 在 200 bytes 內
                    min_dist = dist
                    closest = vcall

            if closest:
                print(f"\n  配對 @ 0x{waddr:08X} - 0x{closest['addr']:08X}")
                print(f"    SetWindowExtEx:   {wcall['params']}")
                print(f"    SetViewportExtEx: {closest['params']}")
                print(f"\n    轉換公式:")
                print(f"      設備座標 = (模板座標 * Viewport) / Window")

                # 嘗試提取數值
                try:
                    if len(wcall['params']) >= 3 and len(closest['params']) >= 3:
                        print(f"      X: device_x = (template_x * {closest['params'][1]}) / {wcall['params'][1]}")
                        print(f"      Y: device_y = (template_y * {closest['params'][2]}) / {wcall['params'][2]}")
                except:
                    pass

    pe.close()


if __name__ == "__main__":
    analyze_coordinate_setup()
