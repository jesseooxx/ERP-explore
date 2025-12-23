"""
追蹤寄存器值 - 找到實際的座標轉換數值
"""

import pefile
from capstone import *
from capstone.x86 import *

EXE_PATH = r"C:\真桌面\Claude code\ERP explore\nrp_backup\nrp32.exe"

def trace_register_backwards(instructions, call_idx: int, target_reg: str, max_depth: int = 50):
    """
    向後追蹤寄存器值

    例如：找到 push edx 之前，edx 被賦值為什麼
    """
    values = []

    for i in range(call_idx - 1, max(0, call_idx - max_depth), -1):
        insn = instructions[i]

        # 檢查是否有對目標寄存器的賦值
        # mov edx, xxx
        if insn.mnemonic == 'mov':
            ops = insn.op_str.split(',')
            if len(ops) == 2:
                dest = ops[0].strip()
                src = ops[1].strip()

                if dest == target_reg:
                    values.append({
                        'addr': insn.address,
                        'instruction': f"{insn.mnemonic} {insn.op_str}",
                        'source': src
                    })

                    # 如果是立即數，直接返回
                    if src.startswith('0x') or src.isdigit():
                        return values

        # lea edx, [xxx]
        elif insn.mnemonic == 'lea':
            ops = insn.op_str.split(',')
            if len(ops) == 2 and ops[0].strip() == target_reg:
                values.append({
                    'addr': insn.address,
                    'instruction': f"{insn.mnemonic} {insn.op_str}",
                    'source': ops[1].strip()
                })

        # 如果遇到函數邊界就停止
        if insn.mnemonic in ['ret', 'retn']:
            break

    return values


def deep_trace_coordinate_values():
    """深度追蹤座標轉換的實際數值"""

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

    print("=" * 70)
    print("深度追蹤座標轉換實際數值")
    print("=" * 70)

    instructions = list(md.disasm(code_data, code_base))

    # 找到 SetWindowExtEx 調用
    for i, insn in enumerate(instructions):
        if insn.mnemonic != 'call':
            continue

        target = None
        if len(insn.operands) > 0:
            op = insn.operands[0]
            if op.type == X86_OP_MEM:
                target = op.mem.disp

        if target and target in imports:
            func_name = imports[target]

            if func_name == 'SetWindowExtEx':
                print(f"\n{'='*70}")
                print(f"SetWindowExtEx @ 0x{insn.address:08X}")
                print(f"{'='*70}")

                # 找前面的 push 指令
                params_raw = []
                for j in range(i-1, max(0, i-10), -1):
                    prev = instructions[j]
                    if prev.mnemonic == 'push':
                        params_raw.append((prev.address, prev.op_str))
                    elif prev.mnemonic in ['call']:
                        break

                params_raw.reverse()

                print(f"\nPush 序列:")
                for addr, param in params_raw:
                    print(f"  0x{addr:08X}: push {param}")

                # SetWindowExtEx(HDC, cx, cy, lpSize)
                # 參數順序（反向）: lpSize, cy, cx, HDC
                if len(params_raw) >= 3:
                    cx_param = params_raw[2][1]  # 第3個 push = cx (寬度)
                    cy_param = params_raw[1][1]  # 第2個 push = cy (高度)

                    print(f"\n參數映射:")
                    print(f"  Window Width (cx):  {cx_param}")
                    print(f"  Window Height (cy): {cy_param}")

                    # 追蹤寄存器值
                    for param_idx, (param_name, param_val) in enumerate([(cx_param, 'cx'), (cy_param, 'cy')]):
                        if param_val in ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi']:
                            print(f"\n  追蹤 {param_name} = {param_val}:")
                            trace = trace_register_backwards(instructions, i, param_val, max_depth=30)
                            for t in trace[:5]:
                                print(f"    0x{t['addr']:08X}: {t['instruction']}")
                                if 'source' in t and (t['source'].startswith('0x') or t['source'].isdigit()):
                                    try:
                                        val = int(t['source'], 0) if '0x' in t['source'] else int(t['source'])
                                        print(f"      → 實際值: {val}")
                                    except:
                                        pass

                # 找對應的 SetViewportExtEx
                print(f"\n尋找對應的 SetViewportExtEx...")
                for j in range(i+1, min(len(instructions), i+50)):
                    next_insn = instructions[j]
                    if next_insn.mnemonic != 'call':
                        continue

                    next_target = None
                    if len(next_insn.operands) > 0:
                        next_op = next_insn.operands[0]
                        if next_op.type == X86_OP_MEM:
                            next_target = next_op.mem.disp

                    if next_target and next_target in imports and imports[next_target] == 'SetViewportExtEx':
                        print(f"  找到 @ 0x{next_insn.address:08X}")

                        # 提取參數
                        vp_params_raw = []
                        for k in range(j-1, max(0, j-10), -1):
                            prev = instructions[k]
                            if prev.mnemonic == 'push':
                                vp_params_raw.append((prev.address, prev.op_str))
                            elif prev.mnemonic in ['call']:
                                break

                        vp_params_raw.reverse()

                        if len(vp_params_raw) >= 3:
                            vp_cx = vp_params_raw[2][1]
                            vp_cy = vp_params_raw[1][1]

                            print(f"  Viewport Width:  {vp_cx}")
                            print(f"  Viewport Height: {vp_cy}")

                            # 追蹤
                            for vp_param_val in [vp_cx, vp_cy]:
                                if vp_param_val in ['eax', 'ebx', 'ecx', 'edx']:
                                    trace = trace_register_backwards(instructions, j, vp_param_val, max_depth=30)
                                    for t in trace[:3]:
                                        if 'source' in t and (t['source'].startswith('0x') or t['source'].isdigit()):
                                            try:
                                                val = int(t['source'], 0) if '0x' in t['source'] else int(t['source'])
                                                print(f"    {vp_param_val}: {val}")
                                            except:
                                                pass

                        break

                if len(params_raw) >= 1:
                    break  # 只分析第一對


    pe.close()


if __name__ == "__main__":
    deep_trace_coordinate_values()
