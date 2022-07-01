using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using LineLogin.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;

namespace LineLogin.Controllers
{
    public class LoginController : Controller
    {
        private readonly HttpClient _httpClient;
        private readonly string _callbackUrl;
        private readonly string _clientId;
        private readonly string _clientSecret;
        private string _authorizedUrl;
        private string _tokenUrl;

        public LoginController(IConfiguration configuration, HttpClient httpClient)
        {
            _clientId = configuration["LineLogin:ClientId"];
            _clientSecret = configuration["LineLogin:ClientSecret"];
            _callbackUrl = configuration["LineLogin:CallbackUrl"];
            _authorizedUrl = configuration["LineLogin:AuthorizeUrl"];
            _tokenUrl = configuration["LineLogin:TokenUrl"];
            _httpClient = httpClient;
        }

        public IActionResult Index()
        {
            if (User.Identity?.IsAuthenticated ?? false)
            {
                return RedirectToAction("Index", "Home");
            }

            return View();
        }

        public IActionResult LineLogin()
        {
            var queryString = QueryString.Create(new List<KeyValuePair<string, string?>>
            {
                new("response_type", "code"),
                new("client_id", _clientId),
                new("redirect_uri", _callbackUrl),
                new("state", "123abc"),
                new("scope", "profile openid"),
            }).Value;
            return Redirect($"{_authorizedUrl}{queryString}");
        }

        public async Task<IActionResult> LineCallback(string code)
        {
            var formDataDictionary = new Dictionary<string, string>
            {
                {"grant_type", "authorization_code"},
                {"code", code},
                {"redirect_uri", _callbackUrl},
                {"client_id", _clientId},
                {"client_secret", _clientSecret},
            };

            var formData = new FormUrlEncodedContent(formDataDictionary);
            var response = await _httpClient.PostAsync(_tokenUrl, formData);
            var token = await response.Content.ReadFromJsonAsync<ResponseToken>();
            // var handler = new JwtSecurityTokenHandler();
            // var idToken = handler.ReadJwtToken(token?.IdToken);
            var idToken = new JwtSecurityToken(token?.IdToken);
            var claimsIdentity = new ClaimsIdentity(idToken.Claims, CookieAuthenticationDefaults.AuthenticationScheme);
            await HttpContext.SignInAsync(new ClaimsPrincipal(claimsIdentity));
            return RedirectToAction("Index", "Home");
        }
    }
}