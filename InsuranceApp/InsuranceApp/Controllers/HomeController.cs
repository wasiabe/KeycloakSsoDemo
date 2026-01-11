using InsuranceApp.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Caching.Memory;
using System.Diagnostics;

namespace InsuranceApp.Controllers
{
    public class HomeController : BaseController
    {
        private readonly IConfiguration _config;
        private readonly TokenManagerService _tokenManagerService1;
        private readonly IMemoryCache _cache;

        public HomeController(
                IHttpClientFactory clientFactory,
                IConfiguration config,
                TokenManagerService tokenManagerService,
                IMemoryCache memoryCache
                ) : base(clientFactory, config, tokenManagerService) 
        {
            _config = config;
            _tokenManagerService1 = tokenManagerService;
            _cache = memoryCache;
        }

        public IActionResult Index()
        {
            // 判斷登入狀態，若尚未登入，手動轉導至 Keycloak
            if ((!User.Identity?.IsAuthenticated ?? true )
                || string.IsNullOrEmpty(_tokenManagerService1.GetIdToken()) )
            {
                //取得OIDC設定
                var ssoRelay = _config["Keycloak:SSORelayLogin"]!;
                var clientId = _config["Keycloak:ClientId"]!;
                var redirectUri = _config["Keycloak:RedirectUri"]!;

                var state = Guid.NewGuid().ToString("N"); // add CSRF protection
                var nonce = Guid.NewGuid().ToString("N"); // for id_token validation

                // 存入 MemoryCache（TTL 短一點）
                var ttl = TimeSpan.FromMinutes(5);
                _cache.Set($"oidc:state:{state}", new { clientId, redirectUri, nonce }, ttl);

                var ssoRelayUrl = QueryHelpers.AddQueryString(
                    ssoRelay,
                    new Dictionary<string, string?>
                    {
                        ["client_id"] = clientId,
                        ["redirect_uri"] = redirectUri,
                        ["state"] = state,
                        ["nonce"] = nonce
                    });

                return Redirect(ssoRelayUrl);
            }

            // 已登入
            return View();
        }

        [Authorize]
        public async Task<IActionResult> Secure()
        {
            // 獲取 Access Token
            string accessToken_session = _tokenManagerService1.GetAccessToken();
            ViewBag.AccessToken = accessToken_session ?? "N/A";

            return View();
        }

        //轉導到集點平台
        public IActionResult RedirectToReward()
        {
            return Redirect("https://localhost:7237/auth/login");
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
