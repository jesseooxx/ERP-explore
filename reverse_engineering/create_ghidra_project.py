"""
創建 Ghidra 自動分析項目並導出結果
如果沒有 Ghidra，則生成 IDA/Binary Ninja 兼容的分析腳本
"""

import os
import json

def generate_ghidra_headless_script():
    """生成 Ghidra headless 分析腳本"""

    script_content = """
# Ghidra Python Script - Analyze nrp32.exe coordinate system
# Run with: analyzeHeadless <project_location> <project_name> -import nrp32.exe -postScript analyze_coords.py

from ghidra.program.model.symbol import *
from ghidra.program.model.listing import *
from ghidra.app.decompiler import *

# Get current program
program = getCurrentProgram()
listing = program.getListing()

print("="*70)
print("Ghidra Auto-Analysis: nrp32.exe Coordinate System")
print("="*70)

# Find all calls to SetMapMode
fm = program.getFunctionManager()
for func in fm.getFunctions(True):
    func_name = func.getName()

    if 'SetMapMode' in func_name or 'TextOut' in func_name:
        print(f"\\nFunction: {func_name} @ {func.getEntryPoint()}")

        # Get all call sites
        refs = func.getSymbol().getReferences()
        for ref in refs:
            if ref.getReferenceType().isCall():
                call_addr = ref.getFromAddress()
                print(f"  Called from: {call_addr}")

                # Get instructions before call
                insn_addr = call_addr.subtract(20)
                for i in range(10):
                    insn = listing.getInstructionAt(insn_addr)
                    if insn:
                        print(f"    {insn.getAddressString(False, False)}: {insn}")
                        insn_addr = insn.getNext().getAddress()

# Export findings
print("\\n" + "="*70)
print("Key Findings Export")
print("="*70)
print("Analysis complete. Check Ghidra GUI for detailed decompilation.")
"""

    output_path = "reverse_engineering/ghidra_analyze_coords.py"
    with open(output_path, 'w') as f:
        f.write(script_content)

    print(f"Ghidra 腳本已生成: {output_path}")
    print("\n使用方法:")
    print("  1. 打開 Ghidra")
    print("  2. 創建新項目並導入 nrp32.exe")
    print("  3. 運行自動分析")
    print("  4. Script Manager > 運行此腳本")

    return output_path


def generate_ida_script():
    """生成 IDA Python 腳本"""

    script_content = """
# IDA Python Script - Analyze nrp32.exe
import idaapi
import idc
import idautils

print("="*70)
print("IDA Auto-Analysis: nrp32.exe")
print("="*70)

# Find SetMapMode calls
for func_ea in idautils.Functions():
    func_name = idc.get_func_name(func_ea)

    if 'SetMapMode' in func_name or 'TextOut' in func_name:
        print(f"\\nFunction: {func_name} @ 0x{func_ea:08X}")

        # Find all xrefs
        for xref in idautils.XrefsTo(func_ea):
            if xref.type == idaapi.fl_CN or xref.type == idaapi.fl_CF:
                call_addr = xref.frm
                print(f"  Called from: 0x{call_addr:08X}")

                # Print instructions before call
                addr = idc.prev_head(call_addr, 20)
                for i in range(10):
                    if addr >= call_addr:
                        break
                    print(f"    0x{addr:08X}: {idc.GetDisasm(addr)}")
                    addr = idc.next_head(addr)

# Find constants
print("\\n" + "="*70)
print("Constant Search")
print("="*70)

constants = [900, 1200, 595, 842, 72, 254]
for const in constants:
    ea = idc.find_imm(0, idaapi.SEARCH_DOWN, const)
    if ea != idaapi.BADADDR:
        print(f"  Found {const} @ 0x{ea:08X}")
"""

    output_path = "reverse_engineering/ida_analyze_coords.py"
    with open(output_path, 'w') as f:
        f.write(script_content)

    print(f"\nIDA 腳本已生成: {output_path}")
    print("\n使用方法:")
    print("  1. 用 IDA Pro 打開 nrp32.exe")
    print("  2. File > Script File > 運行此腳本")

    return output_path


def create_analysis_guide():
    """創建詳細的反彙編分析指南"""

    guide = """
# NRP32.EXE 完整反彙編指南

## 方法 1: 使用 Ghidra (推薦 - 免費)

### 安裝
1. 下載 Ghidra: https://ghidra-sre.org/
2. 解壓並運行 ghidraRun.bat

### 分析步驟
1. 創建新項目: File > New Project
2. 導入文件: File > Import File > 選擇 nrp32.exe
3. 雙擊打開，選擇自動分析 (Yes)
4. 等待分析完成 (~5分鐘)

### 關鍵分析點

#### A. 找到座標轉換代碼
1. 搜索函數: Search > For Functions... > "SetMapMode"
2. 雙擊進入引用
3. 查看反編譯代碼 (右側窗格)
4. 找到 SetWindowExtEx 和 SetViewportExtEx 的參數

#### B. 找到文本渲染函數
1. 搜索 "TextOut"
2. 查看所有調用點
3. 分析座標參數如何計算

#### C. 找到分頁邏輯
1. 搜索 "StartPage" 和 "EndPage"
2. 分析調用條件

### 導出反編譯代碼
1. 選擇函數
2. Right-click > Export > C Code
3. 保存並分享給我

## 方法 2: 使用 IDA Free (強大)

### 安裝
1. 下載 IDA Free: https://hex-rays.com/ida-free/
2. 安裝

### 分析步驟
同 Ghidra，UI 稍有不同

## 方法 3: 使用 Binary Ninja Cloud (在線)

https://cloud.binary.ninja/

## 我需要的信息

如果你能用 Ghidra/IDA 分析，請提供：

### 1. SetWindowExtEx 的實際數值
```c
// 找到類似這樣的代碼
SetMapMode(hdc, MM_ANISOTROPIC);
SetWindowExtEx(hdc, XXX, YYY, NULL);    // XXX, YYY 是什麼數字？
SetViewportExtEx(hdc, AAA, BBB, NULL);  // AAA, BBB 是什麼數字？
```

### 2. 文本渲染函數的反編譯
```c
// 找到調用 TextOutA 的函數
void RenderText(HDC hdc, Element* elem) {
    int x = elem->x * ??? ;  // 乘以什麼？
    int y = elem->y * ??? ;  // 乘以什麼？
    TextOutA(hdc, x, y, text, len);
}
```

### 3. 分頁判斷邏輯
```c
// 何時調用 ShowPage?
if (???) {  // 什麼條件？
    canvas.showPage();
}
```

## 臨時替代方案

如果不想用反彙編工具，也可以：

### 方法 A: 運行時監控 (Process Monitor)
1. 下載 Process Monitor
2. 過濾 nrp32.exe
3. 運行並打開 sample_report.tmp
4. 觀察文件讀取模式

### 方法 B: API Hooking
使用 API Monitor 或 Detours 鉤住 GDI 調用，記錄實際參數

### 方法 C: 暴力匹配 (我來做)
我創建所有可能的座標轉換組合，生成PDF，找最接近的

---

## 下一步

請選擇：
1. [ ] 你用 Ghidra/IDA 分析，分享反編譯結果
2. [ ] 我用暴力方法嘗試所有組合
3. [ ] 我們一起運行 nrp32.exe 並觀察實際輸出
"""

    output_path = "reverse_engineering/DISASSEMBLY_GUIDE.md"
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(guide)

    print(f"\n反彙編指南已創建: {output_path}")

    return output_path


def main():
    print("=" * 70)
    print("創建 Ghidra/IDA 分析項目")
    print("=" * 70)

    # 生成腳本
    ghidra_script = generate_ghidra_headless_script()
    ida_script = generate_ida_script()
    guide = create_analysis_guide()

    print("\n" + "=" * 70)
    print("文件已生成")
    print("=" * 70)
    print(f"\n1. Ghidra 腳本: {ghidra_script}")
    print(f"2. IDA 腳本: {ida_script}")
    print(f"3. 分析指南: {guide}")

    print("\n" + "=" * 70)
    print("下一步建議")
    print("=" * 70)
    print("\n選項 A: 使用 Ghidra/IDA (最準確)")
    print("  - 打開 nrp32.exe")
    print("  - 導出 SetWindowExtEx 和 TextOut 的反編譯代碼")
    print("  - 我將根據實際代碼重寫渲染器")

    print("\n選項 B: 暴力測試 (快速但可能不完美)")
    print("  - 我生成 100+ 種座標轉換組合")
    print("  - 視覺對比找最接近的")
    print("  - 2小時內完成")

    print("\n你想用哪種方法？")


if __name__ == "__main__":
    main()
