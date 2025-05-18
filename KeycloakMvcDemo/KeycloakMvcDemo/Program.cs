using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

var builder = WebApplication.CreateBuilder(args);

// 從 appsettings.json 讀取 Keycloak 配置
var keycloakConfig = builder.Configuration.GetSection("Keycloak");

// 添加 MVC 服務
builder.Services.AddControllersWithViews();

// 配置認證
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
})
.AddCookie()
.AddOpenIdConnect(options =>
{
    options.RequireHttpsMetadata = false;
    options.Authority = keycloakConfig["Authority"];
    options.ClientId = keycloakConfig["ClientId"];
    options.ClientSecret = keycloakConfig["ClientSecret"];
    options.ResponseType = OpenIdConnectResponseType.Code; // 使用 Authorization Code Flow
    options.SaveTokens = true; // 保存 Access Token 和 Refresh Token
    options.GetClaimsFromUserInfoEndpoint = true;
    options.Scope.Add("openid");
    options.Scope.Add("profile");
    options.CallbackPath = "/signin-oidc"; // 必須與 Keycloak 的 Redirect URI 匹配
    options.TokenValidationParameters.NameClaimType = "name"; // 設置使用者名稱的 Claim
});

var app = builder.Build();

// 配置中間件
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();