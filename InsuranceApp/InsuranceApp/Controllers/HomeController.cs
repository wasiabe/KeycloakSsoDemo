using System.Diagnostics;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using InsuranceApp.Models;
using InsuranceApp.Services;

namespace InsuranceApp.Controllers
{
    public class HomeController : BaseController
    {
        private readonly IConfiguration _config;
        private readonly TokenManagerService _tokenManagerService1;

        public HomeController(
                IHttpClientFactory clientFactory,
                IConfiguration config,
                TokenManagerService tokenManagerService
                ) : base(clientFactory, config, tokenManagerService) 
        {
            _config = config;
            _tokenManagerService1 = tokenManagerService;
        }

        public IActionResult Index()
        {
            if ((User.Identity?.IsAuthenticated ?? true )
                || string.IsNullOrEmpty(_tokenManagerService1.GetIdToken()) )
            {
                // 尚未登入，手動轉導至 Keycloak
                var clientId = _config["Keycloak:ClientId"]; 
                var redirectUri = _config["Keycloak:RedirectUri"]; ;

                var keycloakLoginUrl =
                    "http://localhost:8080/realms/tcblife-realm/protocol/openid-connect/auth" +
                    $"?client_id={Uri.EscapeDataString(clientId)}" +
                    $"&redirect_uri={Uri.EscapeDataString(redirectUri)}" +
                    "&response_type=code" +
                    "&scope=openid" +
                    $"&state={Guid.NewGuid():N}";

                return Redirect(keycloakLoginUrl);
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
