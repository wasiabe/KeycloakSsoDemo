using Microsoft.AspNetCore.WebUtilities;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

///======================================================
//無互動模式
//Keycloak 不會顯示任何畫面。如果使用者未登入，會直接返回錯誤；這通常用於檢查登入狀態。
///======================================================
app.MapGet("/sso-relay-silent", async (HttpContext context, IConfiguration config) =>
{
    var query = context.Request.Query;

    var clientId = query["client_id"].ToString();
    var redirectUri = query["redirect_uri"].ToString();

    // 如果 Query String 有傳入 state 則使用，否則產生新的
    var stateFromQuery = query.TryGetValue("state", out var stateVal) ? stateVal.ToString() : null;
    var state = !string.IsNullOrWhiteSpace(stateFromQuery)
        ? stateFromQuery
        : Guid.NewGuid().ToString("N");

    // 如果 Query String 有傳入 nonce 則使用，否則產生新的
    var nonceFromQuery = query.TryGetValue("nonce", out var nonceVal) ? nonceVal.ToString() : null;
    var nonce = !string.IsNullOrWhiteSpace(nonceFromQuery)
        ? nonceFromQuery
        : Guid.NewGuid().ToString("N");

    if (string.IsNullOrWhiteSpace(clientId) || string.IsNullOrWhiteSpace(redirectUri))
    {
        context.Response.StatusCode = 400;
        await context.Response.WriteAsync("Missing client_id or redirect_uri");
        return;
    }

    var authUrl = QueryHelpers.AddQueryString(
        config["Keycloak:OIDCEndpoint"]!,
        new Dictionary<string, string?>
        {
            ["client_id"] = clientId,
            ["redirect_uri"] = redirectUri,
            ["response_type"] = "code",
            ["scope"] = "openid",
            ["prompt"] = "none",    //無互動模式(不顯示登入畫面)
            ["state"] = state,
            ["nonce"] = nonce
        });

    context.Response.Redirect(authUrl);
});

///======================================================
//強制要求登入
//Keycloak 會忽略現有的 Session，強制使用者重新輸入帳號密碼。
///======================================================
app.MapGet("/sso-relay-login", async (HttpContext context, IConfiguration config) =>
{
    var query = context.Request.Query;

    var clientId = query["client_id"].ToString();
    var redirectUri = query["redirect_uri"].ToString();

    // 如果 Query String 有傳入 state 則使用，否則產生新的
    var stateFromQuery = query.TryGetValue("state", out var stateVal) ? stateVal.ToString() : null;
    var state = !string.IsNullOrWhiteSpace(stateFromQuery)
        ? stateFromQuery
        : Guid.NewGuid().ToString("N");

    // 如果 Query String 有傳入 nonce 則使用，否則產生新的
    var nonceFromQuery = query.TryGetValue("nonce", out var nonceVal) ? nonceVal.ToString() : null;
    var nonce = !string.IsNullOrWhiteSpace(nonceFromQuery)
        ? nonceFromQuery
        : Guid.NewGuid().ToString("N");

    if (string.IsNullOrWhiteSpace(clientId) || string.IsNullOrWhiteSpace(redirectUri))
    {
        context.Response.StatusCode = 400;
        await context.Response.WriteAsync("Missing client_id or redirect_uri");
        return;
    }

    var authUrl = QueryHelpers.AddQueryString(
        config["Keycloak:OIDCEndpoint"]!,
        new Dictionary<string, string?>
        {
            ["client_id"] = clientId,
            ["redirect_uri"] = redirectUri,
            ["response_type"] = "code",
            ["scope"] = "openid",
            ["prompt"] = "login",    //強制登入
            ["state"] = state,
            ["nonce"] = nonce
        });

    context.Response.Redirect(authUrl);
});

app.Run();


