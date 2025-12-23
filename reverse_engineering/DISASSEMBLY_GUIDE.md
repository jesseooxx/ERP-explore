
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
