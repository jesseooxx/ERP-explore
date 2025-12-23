"""
完整反彙編 nrp32.exe - IDA 級別分析
重點：渲染函數、座標轉換、GDI 調用
"""

import pefile
from capstone import *
from capstone.x86 import *
import struct
from collections import defaultdict, deque
from typing import Dict, List, Set, Tuple, Optional

EXE_PATH = r"C:\真桌面\Claude code\ERP explore\nrp_backup\nrp32.exe"

class FunctionAnalyzer:
    """函數分析器 - IDA 風格"""

    def __init__(self, pe: pefile.PE):
        self.pe = pe
        self.image_base = pe.OPTIONAL_HEADER.ImageBase
        self.md = Cs(CS_ARCH_X86, CS_MODE_32)
        self.md.detail = True

        # 導入表映射
        self.imports = self._build_import_map()

        # 代碼段
        self.code_section = self._get_code_section()
        self.code_data = self.code_section.get_data()
        self.code_base = self.image_base + self.code_section.VirtualAddress

        # 反彙編緩存
        self.disasm_cache = {}

        # 函數邊界
        self.functions = {}

    def _build_import_map(self) -> Dict[int, Tuple[str, str]]:
        """構建導入表映射"""
        import_map = {}
        if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode('utf-8', errors='ignore')
                for imp in entry.imports:
                    if imp.name:
                        func = imp.name.decode('utf-8', errors='ignore')
                        import_map[imp.address] = (dll, func)
        return import_map

    def _get_code_section(self):
        """獲取代碼段"""
        for section in self.pe.sections:
            name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
            if name == '.text':
                return section
        return None

    def disassemble_at(self, va: int, max_instructions: int = 100) -> List:
        """從指定地址開始反彙編"""
        if va in self.disasm_cache:
            return self.disasm_cache[va]

        offset = va - self.code_base
        if offset < 0 or offset >= len(self.code_data):
            return []

        instructions = []
        for insn in self.md.disasm(self.code_data[offset:offset+500], va):
            instructions.append(insn)
            if len(instructions) >= max_instructions:
                break

        self.disasm_cache[va] = instructions
        return instructions

    def find_function_by_pattern(self, gdi_func: str, context_size: int = 10) -> List[Dict]:
        """
        找到所有調用特定 GDI 函數的位置及上下文

        重點分析：
        - TextOutA: 文本渲染
        - CreateFontIndirectA: 字體創建
        - SetTextAlign: 對齊設置
        - ExtTextOutA: 擴展文本輸出
        """
        results = []

        # 找到目標函數的 IAT 地址
        target_addr = None
        for addr, (dll, func) in self.imports.items():
            if func == gdi_func:
                target_addr = addr
                break

        if not target_addr:
            return results

        print(f"\n分析函數: {gdi_func}")
        print(f"  IAT 地址: 0x{target_addr:08X}")

        # 掃描代碼段找所有 CALL 指令
        instructions = list(self.md.disasm(self.code_data, self.code_base))

        for i, insn in enumerate(instructions):
            if insn.mnemonic != 'call':
                continue

            # 檢查是否調用目標函數
            is_target = False
            if len(insn.operands) > 0:
                op = insn.operands[0]
                if op.type == X86_OP_IMM:
                    if op.imm == target_addr:
                        is_target = True
                elif op.type == X86_OP_MEM:
                    if op.mem.disp == target_addr:
                        is_target = True

            if not is_target:
                continue

            # 提取上下文
            context_start = max(0, i - context_size)
            context_end = min(len(instructions), i + 5)
            context = instructions[context_start:context_end]

            # 分析參數（逆向追踪 push 指令）
            params = self._extract_call_params(instructions, i, gdi_func)

            results.append({
                'address': insn.address,
                'context': context,
                'params': params
            })

        print(f"  找到 {len(results)} 個調用")
        return results

    def _extract_call_params(self, instructions: List, call_idx: int, func_name: str) -> List:
        """
        提取函數調用參數（從 push 指令）

        stdcall 約定：參數從右到左 push
        """
        params = []

        # 向前掃描尋找 push 指令
        for i in range(call_idx - 1, max(0, call_idx - 20), -1):
            insn = instructions[i]

            if insn.mnemonic == 'push':
                if len(insn.operands) > 0:
                    op = insn.operands[0]
                    if op.type == X86_OP_IMM:
                        params.append(('imm', op.imm))
                    elif op.type == X86_OP_REG:
                        params.append(('reg', insn.reg_name(op.reg)))
                    elif op.type == X86_OP_MEM:
                        params.append(('mem', f'[{op.mem.disp:X}]'))

            # 遇到其他 call 或 ret 就停止
            if insn.mnemonic in ['call', 'ret']:
                break

        # 反轉（因為是逆向掃描）
        params.reverse()
        return params

    def analyze_text_rendering_logic(self):
        """深度分析文本渲染邏輯"""
        print("\n" + "=" * 70)
        print("文本渲染邏輯完整分析")
        print("=" * 70)

        # 分析 TextOutA
        textout_calls = self.find_function_by_pattern('TextOutA', context_size=15)

        for idx, call in enumerate(textout_calls[:3]):  # 詳細分析前3個
            print(f"\n--- TextOutA 調用 #{idx+1} @ 0x{call['address']:08X} ---")

            print("\n  上下文代碼:")
            for insn in call['context']:
                marker = " >>> " if insn.address == call['address'] else "     "
                print(f"{marker}0x{insn.address:08X}: {insn.mnemonic:8s} {insn.op_str}")

            print(f"\n  參數分析:")
            print(f"    TextOutA(HDC, x, y, lpString, c)")
            if call['params']:
                for i, (ptype, pval) in enumerate(call['params']):
                    print(f"      參數{i}: {ptype} = {pval}")

        return textout_calls

    def analyze_coordinate_transform(self):
        """分析座標轉換邏輯"""
        print("\n" + "=" * 70)
        print("座標轉換分析")
        print("=" * 70)

        # 查找可能的座標計算代碼
        # 特徵：乘法、除法、加法操作在調用 TextOut 之前

        textout_calls = self.find_function_by_pattern('TextOutA', context_size=20)

        print("\n尋找座標計算模式...")

        for call in textout_calls[:2]:
            print(f"\n調用 @ 0x{call['address']:08X}")
            print("  可能的座標計算:")

            for insn in call['context']:
                # 尋找算術運算
                if insn.mnemonic in ['imul', 'mul', 'idiv', 'div', 'add', 'sub', 'shl', 'shr']:
                    print(f"    0x{insn.address:08X}: {insn.mnemonic:8s} {insn.op_str}")

                # 尋找浮點運算
                if insn.mnemonic.startswith('f'):  # fmul, fadd, etc
                    print(f"    0x{insn.address:08X}: {insn.mnemonic:8s} {insn.op_str} (浮點)")

    def analyze_setmapmode_calls(self):
        """分析 SetMapMode 調用 - 關鍵的座標系統設定"""
        print("\n" + "=" * 70)
        print("SetMapMode 分析（座標映射模式）")
        print("=" * 70)

        calls = self.find_function_by_pattern('SetMapMode', context_size=5)

        print(f"\nSetMapMode 調用模式:")
        print(f"  MM_TEXT = 1       (每單位 = 1 像素)")
        print(f"  MM_LOMETRIC = 2   (每單位 = 0.1 mm)")
        print(f"  MM_HIMETRIC = 3   (每單位 = 0.01 mm)")
        print(f"  MM_LOENGLISH = 4  (每單位 = 0.01 inch)")
        print(f"  MM_HIENGLISH = 5  (每單位 = 0.001 inch)")
        print(f"  MM_TWIPS = 6      (每單位 = 1/1440 inch)")
        print(f"  MM_ISOTROPIC = 7  (自定義，等比例)")
        print(f"  MM_ANISOTROPIC = 8 (自定義，非等比例)")

        for idx, call in enumerate(calls):
            print(f"\n  調用 #{idx+1} @ 0x{call['address']:08X}:")

            # 查看參數（應該是第二個參數）
            if call['params']:
                for i, (ptype, pval) in enumerate(call['params']):
                    if ptype == 'imm' and i == 1:  # 第二個參數是 mode
                        mode_names = {
                            1: "MM_TEXT",
                            2: "MM_LOMETRIC",
                            3: "MM_HIMETRIC",
                            6: "MM_TWIPS",
                            7: "MM_ISOTROPIC",
                            8: "MM_ANISOTROPIC"
                        }
                        mode_name = mode_names.get(pval, f"Unknown({pval})")
                        print(f"      模式: {mode_name}")

            # 顯示上下文
            for insn in call['context']:
                if insn.mnemonic == 'push':
                    print(f"      0x{insn.address:08X}: {insn.mnemonic} {insn.op_str}")

    def deep_analysis_showpage(self):
        """深度分析 ShowPage 類似的函數"""
        print("\n" + "=" * 70)
        print("尋找 ShowPage 渲染函數")
        print("=" * 70)

        # ShowPage 特徵：
        # 1. 調用 SaveDC
        # 2. 調用 SetMapMode
        # 3. 調用 TextOut/ExtTextOut
        # 4. 調用 RestoreDC

        savedc_calls = self.find_function_by_pattern('SaveDC', context_size=50)
        restoredc_calls = self.find_function_by_pattern('RestoreDC', context_size=50)

        print(f"\nSaveDC 調用: {len(savedc_calls)}")
        print(f"RestoreDC 調用: {len(restoredc_calls)}")

        # 找到包含 SaveDC 和 RestoreDC 的函數（可能是 ShowPage）
        print("\n尋找渲染主函數（包含 SaveDC + RestoreDC）...")

        for save_call in savedc_calls[:5]:
            save_addr = save_call['address']

            # 在附近尋找 RestoreDC
            for restore_call in restoredc_calls:
                restore_addr = restore_call['address']

                # 如果在 1000 字節內
                if abs(restore_addr - save_addr) < 1000:
                    print(f"\n  可能的渲染函數:")
                    print(f"    SaveDC @ 0x{save_addr:08X}")
                    print(f"    RestoreDC @ 0x{restore_addr:08X}")
                    print(f"    範圍: {restore_addr - save_addr} bytes")

                    # 分析這個範圍內的所有 GDI 調用
                    self._analyze_function_range(save_addr, restore_addr)
                    break

    def _analyze_function_range(self, start_va: int, end_va: int):
        """分析函數範圍內的所有調用"""
        instructions = self.disassemble_at(start_va, max_instructions=500)

        gdi_calls_found = []
        for insn in instructions:
            if insn.address > end_va:
                break

            if insn.mnemonic == 'call':
                # 檢查是否是 GDI/USER32 函數
                target = self._get_call_target(insn)
                if target and target in self.imports:
                    dll, func = self.imports[target]
                    if dll in ['GDI32.dll', 'USER32.dll']:
                        gdi_calls_found.append((insn.address, func))

        print(f"\n    GDI 調用序列:")
        for addr, func in gdi_calls_found:
            print(f"      0x{addr:08X}: {func}")

    def _get_call_target(self, insn) -> Optional[int]:
        """獲取 CALL 指令的目標地址"""
        if len(insn.operands) > 0:
            op = insn.operands[0]
            if op.type == X86_OP_IMM:
                return op.imm
            elif op.type == X86_OP_MEM:
                return op.mem.disp
        return None

    def find_string_references(self, search_str: str):
        """找到字符串引用"""
        search_bytes = search_str.encode('ascii')

        # 在數據段尋找字符串
        for section in self.pe.sections:
            name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
            if name in ['.rdata', '.data']:
                data = section.get_data()
                offset = 0
                while True:
                    pos = data.find(search_bytes, offset)
                    if pos == -1:
                        break

                    # 計算 VA
                    va = self.image_base + section.VirtualAddress + pos
                    print(f"  '{search_str}' @ 0x{va:08X} (section: {name})")

                    # 尋找引用此地址的代碼
                    self._find_code_references(va)

                    offset = pos + 1
                    break  # 只找第一個

    def _find_code_references(self, data_va: int):
        """尋找代碼中引用某個數據地址的位置"""
        # 簡化版：掃描 push 指令
        instructions = list(self.md.disasm(self.code_data, self.code_base))

        refs = []
        for insn in instructions:
            if insn.mnemonic == 'push':
                if len(insn.operands) > 0:
                    op = insn.operands[0]
                    if op.type == X86_OP_IMM and op.imm == data_va:
                        refs.append(insn.address)
                    elif op.type == X86_OP_MEM and op.mem.disp == data_va:
                        refs.append(insn.address)

        if refs:
            print(f"    引用於: {[f'0x{a:08X}' for a in refs[:5]]}")


def main():
    print("=" * 70)
    print("NRP32.EXE 完整反彙編分析 (IDA 級別)")
    print("=" * 70)

    pe = pefile.PE(EXE_PATH)
    analyzer = FunctionAnalyzer(pe)

    print(f"\n代碼段: 0x{analyzer.code_base:08X}, {len(analyzer.code_data)} bytes")
    print(f"導入函數: {len(analyzer.imports)}")

    # 1. 分析座標映射模式
    analyzer.analyze_setmapmode_calls()

    # 2. 分析文本渲染
    analyzer.analyze_text_rendering_logic()

    # 3. 分析座標轉換
    analyzer.analyze_coordinate_transform()

    # 4. 深度分析 ShowPage
    analyzer.deep_analysis_showpage()

    # 5. 尋找關鍵字符串引用
    print("\n" + "=" * 70)
    print("關鍵字符串引用分析")
    print("=" * 70)

    key_strings = ['PLANK', 'EDIT', 'LABEL', 'HEAD']
    for s in key_strings:
        analyzer.find_string_references(s)

    pe.close()

    print("\n" + "=" * 70)
    print("分析完成")
    print("=" * 70)
    print("\n下一步：")
    print("  1. 根據 SetMapMode 確定座標單位")
    print("  2. 根據 ShowPage 序列重建渲染流程")
    print("  3. 提取座標轉換公式")


if __name__ == "__main__":
    main()
