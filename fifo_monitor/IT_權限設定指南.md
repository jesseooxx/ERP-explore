# 請 IT 幫我開通 SQL Server 權限

## 我要做什麼

我寫了一個小程式，需要**讀取** ERP 資料庫的資料。
程式只會「看」資料，不會改任何東西。

---

## 請 IT 告訴我這些資訊

```
1. 公司 SQL Server 的 IP 或電腦名稱是什麼？

   答：_______________________


2. 我要用什麼方式登入？

   □ 用我的公司電腦帳號（Windows 驗證）

   □ 用另外的帳號密碼（SQL 驗證）
     帳號：_______________
     密碼：_______________
```

---

## 請 IT 幫我做這件事

**讓我的帳號可以「讀取」DATAWIN 資料庫**

### 如果用公司電腦帳號登入

請在 SQL Server 執行這段指令（把 `DOMAIN\我的帳號` 換成我的實際帳號）：

```sql
-- 第一步：讓我的帳號可以連進 SQL Server
CREATE LOGIN [DOMAIN\我的帳號] FROM WINDOWS;

-- 第二步：讓我可以讀 DATAWIN 資料庫
USE DATAWIN;
CREATE USER [DOMAIN\我的帳號] FOR LOGIN [DOMAIN\我的帳號];
ALTER ROLE db_datareader ADD MEMBER [DOMAIN\我的帳號];
```

### 如果要給我另外的帳號密碼

請在 SQL Server 執行這段指令：

```sql
-- 第一步：建立一個新帳號
CREATE LOGIN fifo_reader WITH PASSWORD = '設定一個密碼';

-- 第二步：讓這個帳號可以讀 DATAWIN 資料庫
USE DATAWIN;
CREATE USER fifo_reader FOR LOGIN fifo_reader;
ALTER ROLE db_datareader ADD MEMBER fifo_reader;
```

然後把帳號密碼告訴我。

---

## 如果從我的電腦連不上

可能是防火牆擋住了，請開通：

- **Port 1433**（SQL Server 預設的門）

---

## 補充說明

- 我的程式只會「讀」資料，不會「改」資料
- 只需要看 `tfm01` 和 `tfm03` 這兩個表
- 如果有疑慮，我可以給你看程式碼

---

## 設定好之後

請告訴我：
1. SQL Server 的 IP 或名稱
2. 我要用哪種方式登入
3. （如果是另外的帳號）帳號和密碼

我會測試看看能不能連上，謝謝！
