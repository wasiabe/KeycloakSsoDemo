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

app.MapGet("/sso-relay", async (HttpContext context, IConfiguration config) =>
{
    var query = context.Request.Query;

    var clientId = query["client_id"].ToString();
    var redirectUri = query["redirect_uri"].ToString();

    if (string.IsNullOrWhiteSpace(clientId) || string.IsNullOrWhiteSpace(redirectUri))
    {
        context.Response.StatusCode = 400;
        await context.Response.WriteAsync("Missing client_id or redirect_uri");
        return;
    }

    var state = Guid.NewGuid().ToString("N"); // optional: add CSRF protection
    var nonce = Guid.NewGuid().ToString("N"); // optional: for id_token validation

    var authUrl = QueryHelpers.AddQueryString(
        config["Keycloak:OIDCEndpoint"]!,
        new Dictionary<string, string?>
        {
            ["client_id"] = clientId,
            ["redirect_uri"] = redirectUri,
            ["response_type"] = "code",
            ["scope"] = "openid",
            ["prompt"] = "none",
            ["state"] = state,
            ["nonce"] = nonce
        });

    context.Response.Redirect(authUrl);
});

app.Run();


