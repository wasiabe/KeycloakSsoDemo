using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;

namespace InsuranceApp.Services
{
    public class TokenManagerService
    {
        // Token Status
        private DateTime? _lastRefreshTime;
        private bool _lastRefreshSuccess;
        private DateTime? _accessTokenExpiresAt;
        private DateTime? _refreshTokenExpiresAt;

        private readonly string _idTokenTag = "id_token";
        private readonly string _accessTokenTag = "access_token";
        private readonly string _refreshTokenTag = "refresh_token";

        private readonly IHttpClientFactory _httpClientFactory;
        private readonly IConfiguration _config;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly HttpContext _context;

        public TokenManagerService(
            IHttpClientFactory httpClientFactory,
            IConfiguration config,
            IHttpContextAccessor httpContextAccessor)
        {
            _httpClientFactory = httpClientFactory;
            _config = config;
            _httpContextAccessor = httpContextAccessor;
            _context = _httpContextAccessor.HttpContext!;
        }

        public async Task GetTokenWithAuthorizationCode(string code)
        {
            var tokenEndpoint = _config["Keycloak:TokenEndpoint"];
            var client = _httpClientFactory.CreateClient();

            var response = await client.PostAsync(tokenEndpoint, new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["code"] = code,
                ["client_id"] = _config["Keycloak:ClientId"],
                ["client_secret"] = _config["Keycloak:ClientSecret"],
                ["redirect_uri"] = _config["Keycloak:RedirectUri"]
            }));
            _lastRefreshTime = DateTime.UtcNow;

            if (!response.IsSuccessStatusCode)
            {
                var error = await response.Content.ReadAsStringAsync();
                _lastRefreshSuccess = false;
                Console.WriteLine($"❌ Token exchange failed: {error}");
                return ;
            }

            //解析Token
            var json = await response.Content.ReadAsStringAsync();
            var tokenData = JsonDocument.Parse(json).RootElement;
            var idToken = tokenData.GetProperty("id_token").GetString();
            var accessToken = tokenData.GetProperty("access_token").GetString();
            var refreshToken = tokenData.GetProperty("refresh_token").GetString();

            //儲存Token
            SetIdToken(idToken!);
            SetAccessToken(accessToken!);
            SetRefreshToken(refreshToken!);

            // 記錄 Token Status
            StoreTokenData(tokenData);

            var jwt = new JwtSecurityTokenHandler().ReadJwtToken(idToken);

            //取得nonce
            var tokenNonce = jwt.Claims.FirstOrDefault(c => c.Type == "nonce")?.Value;

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, jwt.Subject ?? ""),
                new Claim(ClaimTypes.Name, jwt.Claims.FirstOrDefault(c => c.Type == "preferred_username")?.Value ?? "")
            };

            var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            var principal = new ClaimsPrincipal(identity);

            await _context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal, new AuthenticationProperties
            {
                IsPersistent = true,
                ExpiresUtc = DateTime.UtcNow.AddMinutes(60)
            });
        }

        /// <summary>
        /// 使用Refresh Token更新Access Token以避免Keycloak Session逾時
        /// </summary>
        /// <returns></returns>
        public async Task EnsureAccessTokenValidAsync()
        {
            // 獲取 Token
            var refreshToken = GetRefreshToken();
            var accessToken = GetAccessToken();

            if (string.IsNullOrEmpty(refreshToken) || string.IsNullOrEmpty(accessToken))
                return;

            var jwtHandler = new JwtSecurityTokenHandler();

            if (!jwtHandler.CanReadToken(accessToken))
                return;

            var jwt = jwtHandler.ReadJwtToken(accessToken);
            var expires = jwt.ValidTo; // UTC
            var now = DateTime.UtcNow;

            if ((expires - now).TotalMinutes > 2)
                return; // token 尚未接近過期則不更新

            // Token 快過期，執行 refresh
            var client = _httpClientFactory.CreateClient();
            var tokenEndpoint = _config["Keycloak:TokenEndpoint"];
            var clientId = _config["Keycloak:ClientId"];
            var clientSecret = _config["Keycloak:ClientSecret"];

            var response = await client.PostAsync(tokenEndpoint,
                new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    ["grant_type"] = "refresh_token",
                    ["refresh_token"] = refreshToken,
                    ["client_id"] = clientId!,
                    ["client_secret"] = clientSecret!
                }));
            _lastRefreshTime = DateTime.UtcNow;

            if (!response.IsSuccessStatusCode)
            {
                var error = await response.Content.ReadAsStringAsync();
                _lastRefreshSuccess = false;
                Console.WriteLine($"❌ Refresh failed: {error}");
                return;
            }

            var json = await response.Content.ReadAsStringAsync();
            var tokenData = JsonDocument.Parse(json).RootElement;

            var newAccessToken = tokenData.GetProperty("access_token").GetString();
            var newRefreshToken = tokenData.GetProperty("refresh_token").GetString();

            //儲存新的Token
            SetAccessToken(newAccessToken);
            SetRefreshToken(newRefreshToken);

            // 記錄 Token Status
            StoreTokenData(tokenData);

            Console.WriteLine($"✅ Token refreshed at {DateTime.Now:HH:mm:ss}");
        }

        public string Logout(string redirectUri)
        {
            // 1. 清除本地登入
            _context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            // 2. 清除本地 cookie
            var idToken = GetIdToken();
            SetIdToken(string.Empty);
            SetAccessToken(string.Empty);
            SetRefreshToken(string.Empty);

            // 3. 準備 Keycloak 登出網址
            var keycloakLogoutUrl = $"{_config["Keycloak:Authority"]}/protocol/openid-connect/logout";

            var logoutUrl = string.IsNullOrEmpty(idToken)
                ? $"{keycloakLogoutUrl}?post_logout_redirect_uri={Uri.EscapeDataString(redirectUri)}"
                : $"{keycloakLogoutUrl}?id_token_hint={idToken}&post_logout_redirect_uri={Uri.EscapeDataString(redirectUri)}";

            return logoutUrl;
        }

        /// <summary>
        /// 儲存 Id Token
        /// </summary>
        /// <param name="token"></param>
        private void SetIdToken( string token)
        {
            _context.Session.SetString(_idTokenTag, token!);
        }

        /// <summary>
        /// 儲存 Access Token
        /// </summary>
        /// <param name="token"></param>
        private void SetAccessToken(string token)
        {
            _context.Session.SetString(_accessTokenTag, token!);
        }

        /// <summary>
        /// 儲存 Refresh Token
        /// </summary>
        /// <param name="token"></param>
        private void SetRefreshToken(string token)
        {
            //Refresh Token 儲存在Server Side是較安全的作法
            //此處因為是作POC,為求便利所以寫入Session
            _context.Session.SetString(_refreshTokenTag, token!);
        }

        /// <summary>
        /// 取得 Id Token
        /// </summary>
        /// <returns></returns>
        public string GetIdToken()
        {
            return _context.Session.GetString(_idTokenTag) ?? "";
        }

        /// <summary>
        /// 取得 Access Token
        /// </summary>
        /// <returns></returns>
        public string GetAccessToken()
        {
            return _context.Session.GetString(_accessTokenTag) ?? "";
        }

        /// <summary>
        /// 取得 Refresh Token
        /// </summary>
        /// <returns></returns>
        public string GetRefreshToken()
        {
            return _context.Session.GetString(_refreshTokenTag) ?? "";
        }

        /// <summary>
        /// 記錄Token資訊
        /// </summary>
        /// <param name="tokenData"></param>
        private void StoreTokenData (JsonElement tokenData)
        {
            _accessTokenExpiresAt = DateTime.UtcNow.AddSeconds(tokenData.GetProperty("expires_in").GetInt32());
            _refreshTokenExpiresAt = DateTime.UtcNow.AddSeconds(tokenData.GetProperty("refresh_expires_in").GetInt32());
            _lastRefreshSuccess = true;

            AppendCookie("LastRefreshTime", _lastRefreshTime?.ToString("u") ?? "N/A");
            AppendCookie("AccessTokenExpiresAt", _accessTokenExpiresAt?.ToString("u") ?? "N/A");
            AppendCookie("RefreshTokenExpiresAt", _refreshTokenExpiresAt?.ToString("u") ?? "N/A");
            AppendCookie("LastRefreshSuccess", _lastRefreshSuccess.ToString() ?? "N/A");

        }

        /// <summary>
        /// 寫入Cookie
        /// </summary>
        /// <param name="key"></param>
        /// <param name="value"></param>
        private void AppendCookie(string key, string value)
        {
            _context.Response.Cookies.Append(key, value, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict
            });
        }
    }
}
