using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Caching.Memory;

public class AuthController : Controller
{
    private readonly IConfiguration _config;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly TokenManagerService _tokenManager;
    private readonly IMemoryCache _cache;

    public AuthController(
        IConfiguration config,
        IHttpClientFactory httpClientFactory,
        TokenManagerService tokenManagerService,
        IMemoryCache memoryCache)
    {
        _config = config;
        _httpClientFactory = httpClientFactory;
        _tokenManager = tokenManagerService;
        _cache = memoryCache;
    }

    [HttpGet("/auth/login")]
    public IActionResult Login()
    {
        //取得OIDC設定
        var ssoRelay = _config["Keycloak:SSORelaySilent"]!;
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

    [HttpGet("/auth/callback")]
    public async Task<IActionResult> Callback([FromQuery] string code, string state)
    {
        if (string.IsNullOrEmpty(code))
            return BadRequest("Missing authorization code");

        //驗證state
        if (!_cache.TryGetValue($"oidc:state:{state}", out dynamic? data) || data is null)
            return Unauthorized("Invalid or expired state.");

        _cache.Remove($"oidc:state:{state}");
        var nonce = (string)data.nonce;

        await _tokenManager.GetTokenWithAuthorizationCode(code, nonce);

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
