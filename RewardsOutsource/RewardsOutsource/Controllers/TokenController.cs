using Microsoft.AspNetCore.Mvc;

namespace RewardsOutsource.Controllers
{
    [Route("token")]
    [ApiController]
    public class TokenController : ControllerBase
    {
        private readonly TokenManagerService _tokenManager;

        public TokenController(TokenManagerService tokenManager)
        {
            _tokenManager = tokenManager;
        }

        [HttpGet("status")]
        public IActionResult GetTokenStatus()
        {
            var lastRefreshTime = Request.Cookies["LastRefreshTime"] ?? "N/A";
            var lastRefreshSuccess = Request.Cookies["LastRefreshSuccess"] ?? "N/A";
            var accessTokenExpiresAt = Request.Cookies["AccessTokenExpiresAt"] ?? "N/A";
            var refreshTokenExpiresAt = Request.Cookies["RefreshTokenExpiresAt"] ?? "N/A";

            return Ok(new
            {
                LastRefreshTime = lastRefreshTime,
                LastRefreshSuccess = lastRefreshSuccess,
                AccessTokenExpiresAt = accessTokenExpiresAt,
                RefreshTokenExpiresAt = refreshTokenExpiresAt
            });
        }
    }
}
