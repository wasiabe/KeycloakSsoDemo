using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
public class AuthController : Controller
{
    private readonly IConfiguration _config;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly TokenManagerService _tokenManager;
    private readonly OidcService _oidcService;

    public AuthController(
        IConfiguration config,
        IHttpClientFactory httpClientFactory,
        TokenManagerService tokenManagerService,
        OidcService oidcService)
    {
        _config = config;
        _httpClientFactory = httpClientFactory;
        _tokenManager = tokenManagerService;
        _oidcService = oidcService;
    }

    [HttpGet("/auth/login")]
    public IActionResult Login()
    {
        //取得OIDC設定
        var ssoRelay = _config["Keycloak:SSORelaySilent"]!;
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

    [HttpGet("/auth/callback")]
    public async Task<IActionResult> Callback([FromQuery] string code, string state)
    {
        if (string.IsNullOrEmpty(code))
            return BadRequest("Missing authorization code");

        //驗證state
        if (!_oidcService.ValidateState(state))
            return Unauthorized("Invalid or expired state.");

        await _tokenManager.GetTokenWithAuthorizationCode(code, state);

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

