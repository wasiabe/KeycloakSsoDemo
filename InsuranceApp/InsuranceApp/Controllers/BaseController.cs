using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using InsuranceApp.Services;

namespace InsuranceApp.Controllers
{
    public class BaseController : Controller
    {
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly IConfiguration _config;
        private readonly TokenManagerService _tokenManager;

        public BaseController(
            IHttpClientFactory httpClientFactory, 
            IConfiguration config,
            TokenManagerService tokenManager
            )
        {
            _httpClientFactory = httpClientFactory;
            _config = config;
            _tokenManager = tokenManager;
        }

        public override async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
        {
            //使用Refresh Token更新AccessToken
            await _tokenManager.EnsureAccessTokenValidAsync();

            // 繼續執行原本的 Action
            await next();
        }
    }
}
