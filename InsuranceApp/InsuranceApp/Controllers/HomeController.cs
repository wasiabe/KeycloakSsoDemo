using InsuranceApp.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using System.Diagnostics;

namespace InsuranceApp.Controllers
{
    public class HomeController : BaseController
    {
        private readonly IConfiguration _config;
        private readonly TokenManagerService _tokenManagerService1;
        private readonly OidcService _oidcService;

        public HomeController(
                IHttpClientFactory clientFactory,
                IConfiguration config,
                TokenManagerService tokenManagerService,
                OidcService oidcService
                ) : base(clientFactory, config, tokenManagerService) 
        {
            _config = config;
            _tokenManagerService1 = tokenManagerService;
            _oidcService = oidcService;
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

                var relatedId = HttpContext.TraceIdentifier;
                var nonce = _oidcService.GenNonce(relatedId);
                var state = _oidcService.GenState(nonce, relatedId, clientId, redirectUri);
                var pkceChallenge = _oidcService.GenPKCEChallengeCode(state, relatedId);

                var ssoRelayUrl = QueryHelpers.AddQueryString(
                    ssoRelay,
                    new Dictionary<string, string?>
                    {
                        ["client_id"] = clientId,
                        ["redirect_uri"] = redirectUri,
                        ["state"] = state,
                        ["nonce"] = nonce,
                        ["code_challenge"] = pkceChallenge,
                        ["code_challenge_method"] = "S256"
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


