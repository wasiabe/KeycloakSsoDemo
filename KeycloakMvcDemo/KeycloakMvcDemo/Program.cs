using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

var builder = WebApplication.CreateBuilder(args);

// �q appsettings.json Ū�� Keycloak �t�m
var keycloakConfig = builder.Configuration.GetSection("Keycloak");

// �K�[ MVC �A��
builder.Services.AddControllersWithViews();

// �t�m�{��
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
    options.ResponseType = OpenIdConnectResponseType.Code; // �ϥ� Authorization Code Flow
    options.SaveTokens = true; // �O�s Access Token �M Refresh Token
    options.GetClaimsFromUserInfoEndpoint = true;
    options.Scope.Add("openid");
    options.Scope.Add("profile");
    options.CallbackPath = "/signin-oidc"; // �����P Keycloak �� Redirect URI �ǰt
    options.TokenValidationParameters.NameClaimType = "name"; // �]�m�ϥΪ̦W�٪� Claim
});

var app = builder.Build();

// �t�m������
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