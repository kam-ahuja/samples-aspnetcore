using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Okta.AspNetCore;
using Okta.Sdk;
using Okta.Sdk.Configuration;
using okta_aspnetcore_mvc_example.Models;
using System.Threading.Tasks;

namespace okta_aspnetcore_mvc_example.Controllers
{
    public class AccountController : Controller
    {
        private OktaSettings _oktaSettings;

        public AccountController(IOptions<OktaSettings> oktaSettings)
        {
            _oktaSettings = oktaSettings.Value;
        }

        public IActionResult Login()
        {
            return View();
        }

        [HttpGet]
        public IActionResult Register(string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Login([FromForm]string sessionToken)
        {
            if (!HttpContext.User.Identity.IsAuthenticated)
            {
                var properties = new AuthenticationProperties();
                properties.Items.Add("sessionToken", sessionToken);
                properties.RedirectUri = "/Home/About";

                return Challenge(properties, OktaDefaults.MvcAuthenticationScheme);
            }

            return RedirectToAction("Index", "Home");
        }


        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model, string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;

            if (ModelState.IsValid)
            {
                var client = new OktaClient(new OktaClientConfiguration
                {
                    OktaDomain = this._oktaSettings.OktaDomain,
                    Token = this._oktaSettings.ApiKey,
                });

                var user = await client.Users.CreateUserAsync(new CreateUserWithPasswordOptions
                {
                    // User profile object
                    Profile = new UserProfile
                    {
                        FirstName = model.FirstName,
                        LastName = model.LasttName,
                        Email = model.Email,
                        Login = model.Login
                    },
                    Password = model.Password,
                    Activate = true
                });
            }
            
            return RedirectToAction("Index", "Home");
        }

        [HttpPost]
        public IActionResult Logout()
        {
            return new SignOutResult(new[] { CookieAuthenticationDefaults.AuthenticationScheme, OktaDefaults.MvcAuthenticationScheme });
        }
    }
}