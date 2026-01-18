using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Caching.Memory;

public sealed class OidcService
{
    private static readonly TimeSpan StateTtl = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan NonceTtl = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan PkceTtl = TimeSpan.FromMinutes(5);

    private readonly IMemoryCache _cache;
    private readonly IHttpContextAccessor _httpContextAccessor;

    public OidcService(IMemoryCache cache, IHttpContextAccessor httpContextAccessor)
    {
        _cache = cache;
        _httpContextAccessor = httpContextAccessor;
    }

    public string GenState(string? nonce, string? relatedId = null, string? clientId = null, string? redirectUri = null)
    {
        var state = BuildTraceableToken(relatedId);
        var data = new StateCacheData(nonce, clientId, redirectUri, relatedId ?? GetTraceId(), DateTime.UtcNow);

        _cache.Set(GetStateKey(state), data, StateTtl);

        return state;
    }

    public bool ValidateState(string state)
    {
        if (string.IsNullOrWhiteSpace(state))
            return false;

        var key = GetStateKey(state);

        if (!_cache.TryGetValue(key, out StateCacheData? _))
            return false;

        _cache.Remove(key);
        return true;
    }

    public string GenNonce(string? relatedId = null)
    {
        var nonce = BuildTraceableToken(relatedId);
        var data = new NonceCacheData(relatedId ?? GetTraceId(), DateTime.UtcNow);

        _cache.Set(GetNonceKey(nonce), data, NonceTtl);

        return nonce;
    }

    public bool ValidateNonce(string nonce)
    {
        if (string.IsNullOrWhiteSpace(nonce))
            return false;

        var key = GetNonceKey(nonce);

        if (!_cache.TryGetValue(key, out NonceCacheData? _))
            return false;

        _cache.Remove(key);
        return true;
    }

    public string GenPKCEChallengeCode(string state, string? relatedId = null)
    {
        if (string.IsNullOrWhiteSpace(state))
            throw new ArgumentException("State is required for PKCE generation.", nameof(state));

        var codeVerifier = GenerateCodeVerifier();
        var codeChallenge = GenerateCodeChallenge(codeVerifier);
        var data = new PkceCacheData(codeVerifier, codeChallenge, relatedId ?? GetTraceId(), DateTime.UtcNow);

        _cache.Set(GetPkceKey(state), data, PkceTtl);

        return codeChallenge;
    }

    public string? GetPKCEChallengeCode(string state)
    {
        if (string.IsNullOrWhiteSpace(state))
            return null;

        var key = GetPkceKey(state);

        if (!_cache.TryGetValue(key, out PkceCacheData? data) || data is null)
            return null;

        _cache.Remove(key);
        // Return code_verifier for the token exchange.
        return data.CodeVerifier;
    }

    private static string GenerateCodeVerifier()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        return WebEncoders.Base64UrlEncode(bytes);
    }

    private static string GenerateCodeChallenge(string codeVerifier)
    {
        var bytes = SHA256.HashData(Encoding.ASCII.GetBytes(codeVerifier));
        return WebEncoders.Base64UrlEncode(bytes);
    }

    private string GetTraceId()
    {
        return _httpContextAccessor.HttpContext?.TraceIdentifier ?? Guid.NewGuid().ToString("N");
    }

    private static string BuildTraceableToken(string? relatedId)
    {
        var token = Guid.NewGuid().ToString("N");

        if (string.IsNullOrWhiteSpace(relatedId))
            return token;

        return $"{token}-{SanitizeRelatedId(relatedId)}";
    }

    private static string SanitizeRelatedId(string relatedId)
    {
        var builder = new StringBuilder(relatedId.Length);

        foreach (var ch in relatedId)
        {
            if ((ch >= 'a' && ch <= 'z')
                || (ch >= 'A' && ch <= 'Z')
                || (ch >= '0' && ch <= '9')
                || ch == '-'
                || ch == '_')
            {
                builder.Append(ch);
            }
            else
            {
                builder.Append('-');
            }
        }

        return builder.ToString();
    }

    private static string GetStateKey(string state) => $"oidc:state:{state}";
    private static string GetNonceKey(string nonce) => $"oidc:nonce:{nonce}";
    private static string GetPkceKey(string state) => $"oidc:pkce:{state}";

    private sealed record StateCacheData(
        string? Nonce,
        string? ClientId,
        string? RedirectUri,
        string RelatedId,
        DateTime CreatedUtc);

    private sealed record NonceCacheData(
        string RelatedId,
        DateTime CreatedUtc);

    private sealed record PkceCacheData(
        string CodeVerifier,
        string CodeChallenge,
        string RelatedId,
        DateTime CreatedUtc);
}
