# Introduction 
這是Keycloak Realm的Export JSON

# Getting Started
由於Keycloak預設禁止用匯入JSON的方式建立Realm,
請依下列方法啟動Keycloak：
1. 關閉目前的 Keycloak 視窗。
2. 執行 kc.bat build --features=scripts (先進行建置)。
3. 執行 kc.bat start-dev --features=scripts。

# 注意事項
在 Keycloak 26.1.2 版本中，你會遇到這個錯誤是因為一個著名的「版本矛盾」：Keycloak 在匯出包含「授權（Authorization）」功能的 Realm 時，會自動產生一個類型為 js 的 Default Policy；但在 Keycloak 18 之後，官方因為安全性考量，已經徹底移除了 upload_scripts 這個 Feature 標籤。
即使你沒有寫任何腳本，只要你的 Client 開啟了 Authorization Enabled，Keycloak 26 就會自動生成如下的 JS 策略：
"type": "js", "code": "// by default, grants any permission... $evaluation.grant();"
當你嘗試匯入這個 JSON 時，系統偵測到裡面含有 JavaScript 代碼，但因為 upload_scripts 功能已被移除且預設禁用，所以報錯。

修正方式:
步驟 1：搜尋"Default Policy", 刪除該策略
搜尋關鍵字："type": "js"。

你會找到類似這樣的區塊：

JSON

{
  "name": "Default Policy",
  "type": "js",
  "logic": "POSITIVE",
  "decisionStrategy": "AFFIRMATIVE",
  "config": {
    "code": "// by default, grants any permission associated with this policy\n$evaluation.grant();\n"
  }
}
將這個整個物件從 policies 陣列中刪除。

步驟 2：搜尋 "Default Permission"
在 JSON 檔案中搜尋 "name": "Default Permission"，您會看到類似下方的結構：

JSON

{
  "name": "Default Permission",
  "type": "resource",
  "logic": "POSITIVE",
  "decisionStrategy": "UNANIMOUS",
  "config": {
    "resources": "[\"Default Resource\"]",
    "applyPolicies": "[\"Default Policy\"]"  <-- 問題就在這一行
  }
}

步驟 3：修改 applyPolicies
將 applyPolicies 裡面的內容清空，改成空的陣列字串：

修改前： "applyPolicies": "[\"Default Policy\"]"

修改後： "applyPolicies": "[]"
