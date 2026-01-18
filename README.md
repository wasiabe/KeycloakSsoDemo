# **目的：**
演示採用　OIDC Authorization Code Flow 搭配 Token Relay 架構實現跨域Single Sign On (SSO)

# **背景：**
公司目前已有網路投保網站,　網址是　https://insurance.mycompany.com 正在規劃一個新的集點平台網站,此網站會委外開發及管理,網址是　https://rewards.outsource.com 
因集點平台網站是委外管理,　域名與網路投保不同,　無法使用Cookie實現SSO,　所以計劃採用 OIDC Authorization Code Flow + Token Relay　架構實現　SSO 

#**方案簡述：**
讓兩個網站都使用 **Keycloak 作為共用身份來源（IdP）**，流程如下：
### 登入流程（Authorization Code Flow）：
1.  使用者造訪任一網站（例如集點網站）
2.  該網站偵測使用者未登入，導向 Keycloak登入頁  
3.  Keycloak 偵測已登入（因另一網站已登入並有 session），直接跳轉回 redirect_uri
4.  網站使用 code 換取 access token / ID token，登入完成

#**為什麼此方案可以實現跨域SSO：**
因為所有網站皆使用Keycloak登入,完成登入後Token儲存在Keycloak網站的Cookie,當網站採用Authorization Code Flow 轉換到Keycloak時,Keycloak即可判斷使用者登入狀況, 若已登入便產生Authentication Code

#**Repos：**

| **Repo Name** | **Port** | **Description** |
|--|--|--|
| KeycloakMvcDemo | 7199 | 使用微軟套件實作OIDC |
| SSOGateway | 7245 | Demo網站,集點網站及保險網站間的SSO轉接閘道 |
| InsuranceAPP | 7298 | 模擬保檢網站 |
| RewardOutsource |  | 模擬委外的集點平台 |


#**Auth Flow Checklist**

1.  Start from GET /auth/login and GET / (unauthenticated) and verify redirects to Keycloak:SSORelaySilent and Keycloak:SSORelayLogin respectively.
2. Confirm the redirect includes state, nonce, code_challenge, and code_challenge_method=S256 in the query.
3. In SSOGateway, verify it forwards code_challenge (+ method) to Keycloak:OIDCEndpoint for both /sso-relay-silent and /sso-relay-login.
4. After Keycloak callback, verify /auth/callback rejects missing/invalid state and accepts valid state once, then fails on replay.
5. Confirm token exchange uses code_verifier (derived from state) and succeeds when code_challenge was sent.
6. Verify nonce validation succeeds once, then fails if the same id_token nonce is replayed.
7. Ensure successful flow signs in and redirects to Home/Secure, and access token is visible in the view.
8. Negative test: remove code_challenge from the initial request and confirm PKCE is skipped but flow still works (if Keycloak allows).

