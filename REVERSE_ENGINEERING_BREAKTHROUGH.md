# 逆向工程突破 - 找到真實座標計算！

## 關鍵發現

### 地址: 0x0040AA95

找到了 **4 對 imul/idiv 操作** - 這就是座標縮放的核心代碼！

## 代碼序列

```assembly
; 第一組: X 座標縮放
0x0040AA92: mov eax, dword ptr [ebp - 0x50]
0x0040AA95: imul eax, dword ptr [ebp - 0x24]     ; eax *= [ebp-0x24]
0x0040AA99: cdq
0x0040AA9A: idiv dword ptr [ebp - 0x470]         ; eax /= [ebp-0x470]
0x0040AAA0: mov dword ptr [ebp - 0x9f0], eax     ; 保存結果

; 浮點調整
0x0040AAA6: fild dword ptr [ebp - 0x9f0]         ; 轉為浮點
0x0040AAAC: fadd qword ptr [0x44b5b0]            ; 加上某個常量
0x0040AAB2: call 0x4372fc                         ; 轉換回整數
0x0040AAB7: mov dword ptr [ebp - 0x50], eax      ; 最終 X

; 第二組: Y 座標縮放
0x0040AABA: mov eax, dword ptr [ebp - 0x54]
0x0040AABD: imul eax, dword ptr [ebp - 0x28]     ; eax *= [ebp-0x28]
0x0040AAC1: cdq
0x0040AAC2: idiv dword ptr [ebp - 0x46c]         ; eax /= [ebp-0x46c]
0x0040AAC8: mov dword ptr [ebp - 0x9f4], eax     ; 保存結果

; 浮點調整
0x0040AACE: fild dword ptr [ebp - 0x9f4]         ; 轉為浮點
0x0040AAD4: fadd qword ptr [0x44b5b0]            ; 加上某個常量
0x0040AADA: call 0x4372fc                         ; 轉換回整數
0x0040AADF: mov dword ptr [ebp - 0x54], eax      ; 最終 Y

; 第三組: 另一個 X 計算
0x0040AAE2: mov eax, dword ptr [ebp - 0x474]
0x0040AAE8: imul eax, dword ptr [ebp - 0x50]
0x0040AAEC: cdq
0x0040AAED: idiv dword ptr [ebp - 0x24]
0x0040AAF0: mov dword ptr [ebp - 0x9f8], eax

; 第四組: 另一個 Y 計算
0x0040AB0A: mov eax, dword ptr [ebp - 0x478]
0x0040AB10: imul eax, dword ptr [ebp - 0x54]
0x0040AB14: cdq
0x0040AB15: idiv dword ptr [ebp - 0x28]
```

## 座標轉換公式（推導）

### 基本公式

```
X_scaled = (X_original * [ebp-0x24]) / [ebp-0x470]
Y_scaled = (Y_original * [ebp-0x28]) / [ebp-0x46c]
```

之後有浮點調整（四捨五入）

### 關鍵變量

需要找到這些棧變量的值：

| 變量 | 用途 | 可能的值 |
|------|------|---------|
| `[ebp-0x24]` | X 乘數 | viewport_width? |
| `[ebp-0x470]` | X 除數 | window_width? |
| `[ebp-0x28]` | Y 乘數 | viewport_height? |
| `[ebp-0x46c]` | Y 除數 | window_height? |
| `[ebp-0x474]` | 偏移/邊距？ | 15 (0xF) |
| `[ebp-0x478]` | 偏移/邊距？ | 15 (0xF) |

### 關聯到 GDI 調用

根據之前分析，在座標計算之後會調用：

```
SetMapMode(hdc, MM_ANISOTROPIC)
SetViewportExtEx(hdc, viewport_w, viewport_h, ...)
SetWindowExtEx(hdc, window_w, window_h, ...)
```

**因此**：
- `window_w/h` = 模板的邏輯尺寸
- `viewport_w/h` = 實際設備尺寸（像素或點數）

## 下一步：提取實際數值

### 方法 1: 動態調試（最準確）

使用 x32dbg 或 WinDbg：
1. 在 0x0040AA95 設置斷點
2. 運行 nrp32.exe 並打開 sample_report.tmp
3. 查看 [ebp-0x24], [ebp-0x28], [ebp-0x470], [ebp-0x46c] 的值

### 方法 2: 靜態追蹤（繼續反彙編）

向前追蹤 200+ 條指令，找到對這些棧變量的賦值

### 方法 3: 使用 Ghidra 反編譯

Ghidra 可以自動重建高級代碼，顯示這些變量的來源

## 當前狀態

✅ 確認使用 MM_ANISOTROPIC 模式
✅ 找到縮放計算代碼（imul/idiv）
✅ 理解公式結構

⚠️ 還需要具體數值

## 臨時解決方案

基於找到的常量（595, 842, 210, 297, 72），推測：

### 推測 1: 直接 point 映射

```python
# 如果 window = 模板座標空間 (900, 1200)
# viewport = 設備空間 (595, 842 - A4 points)

scale_x = 595 / 900  ≈ 0.661
scale_y = 842 / 1200 ≈ 0.702

# 這與我們之前的測試 test_02, test_05 一致！
```

### 推測 2: GetDeviceCaps 動態獲取

```python
# nrp32.exe 可能在運行時調用:
dpi_x = GetDeviceCaps(hdc, LOGPIXELSX)  # 通常 96 或 72
dpi_y = GetDeviceCaps(hdc, LOGPIXELSY)

page_width_pixels = GetDeviceCaps(hdc, HORZRES)
page_height_pixels = GetDeviceCaps(hdc, VERTRES)

# 然後基於 DPI 和實際設備計算縮放
```

## 建議

**立即測試**:
- 試試 `test_02_A4縮放-翻轉Y.pdf`
- 或 `test_05_頁面比例-翻轉Y.pdf`

這兩個最接近推導出的公式！

---

*突破時間: 2025-12-23*
*下一步: 驗證推測的縮放因子*
