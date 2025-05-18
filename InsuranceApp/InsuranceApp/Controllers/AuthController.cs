using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using InsuranceApp.Services;

public class AuthController : Controller
{
    private readonly IConfiguration _config;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly TokenManagerService _tokenManager;

    public AuthController(
        IConfiguration config, 
        IHttpClientFactory httpClientFactory,
        TokenManagerService tokenManagerService)
    {
        _config = config;
        _httpClientFactory = httpClientFactory;
        _tokenManager = tokenManagerService;
    }

    [HttpGet("/auth/login")]
    public IActionResult Login()
    {
        //取得OIDC設定
        var ssoRelay = _config["Keycloak:SSORelay"]!;
        var clientId = _config["Keycloak:ClientId"]!;
        var redirectUri = _config["Keycloak:RedirectUri"]!;

        var ssoRelayUrl = QueryHelpers.AddQueryString(
            ssoRelay,
            new Dictionary<string, string?>
            {
                ["client_id"] = clientId,
                ["redirect_uri"] = redirectUri
            });

        return Redirect(ssoRelayUrl);
    }

    [HttpGet("/auth/callback")]
    public async Task<IActionResult> Callback([FromQuery] string code)
    {
        if (string.IsNullOrEmpty(code))
            return BadRequest("Missing authorization code");

        await _tokenManager.GetTokenWithAuthorizationCode(code);

        return RedirectToAction("Secure", "Home");
    }

    [HttpGet("/auth/logout")]
    public async Task<IActionResult> Logout()
    {
        var redirectUri = Url.Action("Index", "Home", null, Request.Scheme)!;
        var logoutUrl = _tokenManager.Logout(redirectUri);

        return Redirect(logoutUrl);
    }
}
