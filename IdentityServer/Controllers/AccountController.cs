using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using IdentityServer.Models;
using IdentityServer.Models.AccountViewModels;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using IdentityModel;
using IdentityServer4.Extensions;
using Microsoft.Extensions.Logging;
using System.Collections.Generic;
using IdentityServer4.Events;
using Microsoft.AspNetCore.Http;
using System.Security.Principal;
using IdentityServer.Data;
using Microsoft.Extensions.Options;
using MongoDB.Driver;
using IdentityServer.CultureResources;
using System.Web;
using MassTransit;
using IdentityServer.Models.ManageViewModels;
using IdentityServer.Extensions;
using Contracts.Commands;
using Contracts.Models;

namespace IdentityServer.Controllers
{
    [Authorize]
    [Route("[controller]/[action]")]
    public class AccountController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly ILogger _logger;
        private readonly IIdentityServerInteractionService _interaction;
        private readonly IClientStore _clientStore;
        private readonly IPersistedGrantService _persistedGrantService;
        private readonly IEventService _events;
        private readonly IAuthenticationSchemeProvider _schemeProvider;
        protected ApplicationDbContext _context;
        private readonly LocService _localizer;
        private readonly IPublishEndpoint _publishEndpoint;
        private readonly IRequestClient<ICountSendActiveAccount, ISendActiveAccountCounted> _countSendActiveAccountRequestClient;

        public AccountController(
            UserManager<ApplicationUser> userManager,
            IPersistedGrantService persistedGrantService,
            SignInManager<ApplicationUser> signInManager,
            ILoggerFactory loggerFactory,
            IIdentityServerInteractionService interaction,
            IClientStore clientStore,
            IEventService events,
            IAuthenticationSchemeProvider schemeProvider,
            IOptions<MongoDBSettings> settings,
            LocService localizer,
            IPublishEndpoint publishEndpoint,
            IRequestClient<ICountSendActiveAccount, ISendActiveAccountCounted> countSendActiveAccountRequestClient)
        {
            _userManager = userManager;
            _persistedGrantService = persistedGrantService;
            _signInManager = signInManager;
            _logger = loggerFactory.CreateLogger<AccountController>();
            _interaction = interaction;
            _clientStore = clientStore;
            _schemeProvider = schemeProvider;
            _events = events;
            _context = new ApplicationDbContext(settings);
            _localizer = localizer;
            _publishEndpoint = publishEndpoint;
            _countSendActiveAccountRequestClient = countSendActiveAccountRequestClient;
        }

        //
        // GET: /Account/Login
        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> Login(string returnUrl = null)
        {
            // build a model so we know what to show on the login page
            var vm = await BuildLoginViewModelAsync(returnUrl);

            if (vm.IsExternalLoginOnly)
            {
                // we only have one option for logging in and it's an external provider
                return await ExternalLogin(vm.ExternalLoginScheme, returnUrl);
            }

            return View(vm);
        }

        [HttpGet]
        public async Task<IActionResult> VerifyAccount(string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            var user = await _userManager.GetUserAsync(User);
            return View(new VerifyAccountViewModel { Phone = user.PhoneNumber, Email = user.Email });
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> VerifyAccount(VerifyAccountViewModel model, string returnUrl = null)
        {
            if (ModelState.IsValid)
            {
                await Task.Run(async () =>
                {
                    await SendCode(model.VerifyType);
                });
                return RedirectToAction("ActiveAccount", new { returnUrl, verifyType = model.VerifyType });
            }
            return View(model);
        }

        [HttpGet]
        public async Task<long> SendCode(string verifyType)
        {
            var user = await _userManager.GetUserAsync(User);
            var code = string.Empty;
            ISendActiveAccountCounted data = await _countSendActiveAccountRequestClient.Request(
                new
                {
                    UserId = user.Id,
                    VerifyType = verifyType
                });
            if (data.Count >= 5)
            {
                return data.Count;
            }
            else
            {
                switch (verifyType)
                {
                    case "Email":
                        code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                        await _publishEndpoint.Publish<ISendMail>(
                                new
                                {
                                    TypeNotification = TypeNotification.VerifyAccount,
                                    Culture = System.Globalization.CultureInfo.CurrentCulture.Name,
                                    ObjectId = user.Id,
                                    ObjectType = "users",
                                    Data = new DataSendMail()
                                    {
                                        Receiver = user.Email,
                                        Body = code
                                    }
                                });
                        break;
                    case "SMS":
                        code = await _userManager.GenerateChangePhoneNumberTokenAsync(user, user.PhoneNumber);
                        await _publishEndpoint.Publish<ISendSMS>(
                           new
                           {
                               TypeNotification = TypeNotification.VerifyAccount,
                               Culture = System.Globalization.CultureInfo.CurrentCulture.Name,
                               ObjectId = user.Id,
                               ObjectType = "users",
                               Data = new DataSendSMS()
                               {
                                   Phone = user.PhoneNumber,
                                   Message = code
                               }
                           });
                        break;
                    default:
                        break;
                }
                return data.Count + 1;
            }
        }

        [HttpGet]
        public async Task<IActionResult> ActiveAccount(string verifyType, string returnUrl = null)
        {
            var user = await _userManager.GetUserAsync(User);
            ISendActiveAccountCounted data = await _countSendActiveAccountRequestClient.Request(
            new
            {
                UserId = user.Id,
                VerifyType = verifyType
            });
            ViewData["returnUrl"] = returnUrl;
            return View(new VerifyViewModel() { VerifyType = verifyType, CountSendNotification = data.Count });
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ActiveAccount(VerifyViewModel model, string returnUrl = null)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.GetUserAsync(User);
                var result = new IdentityResult();
                switch (model.VerifyType)
                {
                    case "Email":
                        result = await _userManager.ConfirmEmailAsync(user, model.Code);
                        break;
                    case "SMS":
                        result = await _userManager.ChangePhoneNumberAsync(user, user.PhoneNumber, model.Code);
                        break;
                    default:
                        break;
                }

                if (result.Succeeded)
                {
                    user.IsActive = true;
                    await _userManager.UpdateAsync(user);
                    await _signInManager.SignInAsync(user, isPersistent: false);
                    if (String.IsNullOrEmpty(returnUrl))
                    {
                        return RedirectToAction("Index", "Company");
                    }
                    return RedirectToLocal(returnUrl);
                }
                else if (user.IsActive == true)
                {
                    ModelState.AddModelError("Code", _localizer.GetLocalizedHtmlString("activated"));
                }
                else
                {
                    ModelState.AddModelError("Code", _localizer.GetLocalizedHtmlString("invalidActivation"));
                }
            }
            return View(model);
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult GetStarted()
        {
            return View();
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult Register()
        {
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = new ApplicationUser { UserName = model.UserName, PhoneNumber = model.Phone, Email = model.UserName, FirstName = model.FirstName, LastName = model.LastName, CreatedAt = DateTime.Now };
                var result = await _userManager.CreateAsync(user, model.Password);
                if (result.Succeeded)
                {
                    _logger.LogInformation("User created a new account with password.");

                    user = await _userManager.FindByIdAsync(user.Id);
                    await _signInManager.SignInAsync(user, isPersistent: false);
                    _logger.LogInformation("User created a new account with password.");
                    return RedirectToAction("VerifyAccount");
                }
                else
                {
                    foreach (var item in result.Errors)
                    {
                        ModelState.AddModelError("UserName", _localizer.GetLocalizedHtmlString(item.Code));
                    }

                }
            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }

        //
        // POST: /Account/Login
        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> Login(LoginInputModel model)
        {
            var returnUrl = model.ReturnUrl;

            ViewData["ReturnUrl"] = returnUrl;
            if (ModelState.IsValid)
            {
                // This doesn't count login failures towards account lockout
                // To enable password failures to trigger account lockout, set lockoutOnFailure: true
                var user = _userManager.Users.Where(s => s.UserName == model.Username || s.Email == model.Username || s.PhoneNumber == model.Username).FirstOrDefault();
                if (user != null)
                {
                    var link = new Uri(Environment.GetEnvironmentVariable("GATEWAY_API_URL") + returnUrl);
                    string companyId = HttpUtility.ParseQueryString(link.Query).Get("client_id");
                    bool exist = user.Companies.Contains(companyId);
                    if (!exist && !string.IsNullOrEmpty(companyId))
                    {
                        var company = _context.Company.AsQueryable().FirstOrDefault(p => p.Id == companyId);
                        ModelState.AddModelError("Username", _localizer.GetLocalizedHtmlString("usernameNotContainCompany") + " " + company.CompanyName);
                        return View(await BuildLoginViewModelAsync(model));
                    }
                    var result = await _signInManager.PasswordSignInAsync(user, model.Password, model.RememberLogin, lockoutOnFailure: false);
                    if (result.Succeeded)
                    {
                        if (user.IsActive)
                        {
                            _logger.LogInformation(1, "User logged in.");
                            if (String.IsNullOrEmpty(returnUrl))
                            {
                                return RedirectToAction("Index", "Company");
                            }
                            return RedirectToLocal(returnUrl);
                        }
                        else
                        {
                            return RedirectToAction("VerifyAccount", new { returnUrl });
                        }
                    }
                    if (result.IsLockedOut)
                    {
                        _logger.LogWarning(2, "User account locked out.");
                        return View("Lockout");
                    }
                    else
                    {
                        ModelState.AddModelError("Username", _localizer.GetLocalizedHtmlString("loginAttempt"));
                        return View(await BuildLoginViewModelAsync(model));
                    }
                }
                else
                {
                    ModelState.AddModelError("Username", _localizer.GetLocalizedHtmlString("usernameNotExits"));
                    return View(await BuildLoginViewModelAsync(model));
                }

            }

            // If we got this far, something failed, redisplay form
            return View(await BuildLoginViewModelAsync(model));
        }

        async Task<LoginViewModel> BuildLoginViewModelAsync(string returnUrl)
        {
            var context = await _interaction.GetAuthorizationContextAsync(returnUrl);
            if (context?.IdP != null)
            {
                // this is meant to short circuit the UI and only trigger the one external IdP
                return new LoginViewModel
                {
                    EnableLocalLogin = false,
                    ReturnUrl = returnUrl,
                    Username = context?.LoginHint,
                    ExternalProviders = new ExternalProvider[] { new ExternalProvider { AuthenticationScheme = context.IdP } }
                };
            }

            var schemes = await _schemeProvider.GetAllSchemesAsync();

            var providers = schemes
                .Where(x => x.DisplayName != null ||
                            (x.Name.Equals(AccountOptions.WindowsAuthenticationSchemeName, StringComparison.OrdinalIgnoreCase))
                )
                .Select(x => new ExternalProvider
                {
                    DisplayName = x.DisplayName,
                    AuthenticationScheme = x.Name
                }).ToList();

            var allowLocal = true;
            var logoUrl = string.Empty;
            var companyName = string.Empty;
            if (context?.ClientId != null)
            {
                var client = await _clientStore.FindEnabledClientByIdAsync(context.ClientId);
                if (client != null)
                {
                    allowLocal = client.EnableLocalLogin;

                    if (client.IdentityProviderRestrictions != null && client.IdentityProviderRestrictions.Any())
                    {
                        providers = providers.Where(provider => client.IdentityProviderRestrictions.Contains(provider.AuthenticationScheme)).ToList();
                    }
                }

                var company = _context.Company.AsQueryable().SingleOrDefault(s => s.Id == context.ClientId);
                if (company != null)
                {
                    logoUrl = company.LogoUrl;
                    companyName = company.CompanyName;
                }
            }

            return new LoginViewModel
            {
                RememberLogin = AccountOptions.AllowRememberLogin,
                EnableLocalLogin = allowLocal && AccountOptions.AllowLocalLogin,
                ReturnUrl = returnUrl,
                Username = context?.LoginHint,
                ExternalProviders = providers.ToArray(),
                LogoUrl = logoUrl,
                CompanyName = companyName
            };
        }

        async Task<LoginViewModel> BuildLoginViewModelAsync(LoginInputModel model)
        {
            await _interaction.GetAuthorizationContextAsync(model.ReturnUrl);
            var vm = await BuildLoginViewModelAsync(model.ReturnUrl);
            vm.Username = model.Username;
            vm.RememberLogin = model.RememberLogin;
            return vm;
        }

        /// <summary>
        /// Show logout page
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> Logout(string logoutId)
        {
            // build a model so the logout page knows what to display
            var vm = await BuildLogoutViewModelAsync(logoutId);

            if (vm.ShowLogoutPrompt == false)
            {
                // if the request for logout was properly authenticated from IdentityServer, then
                // we don't need to show the prompt and can just log the user out directly.
                return await Logout(vm);
            }

            return View(vm);
        }

        /// <summary>
        /// Handle logout page postback
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout(LogoutInputModel model)
        {
            // build a model so the logged out page knows what to display
            var vm = await BuildLoggedOutViewModelAsync(model.LogoutId);

            if (User?.Identity.IsAuthenticated == true)
            {
                // delete local authentication cookie
                await _signInManager.SignOutAsync();

                // raise the logout event
                await _events.RaiseAsync(new UserLogoutSuccessEvent(User.GetSubjectId(), User.GetDisplayName()));
            }

            // check if we need to trigger sign-out at an upstream identity provider
            if (vm.TriggerExternalSignout)
            {
                // build a return URL so the upstream provider will redirect back
                // to us after the user has logged out. this allows us to then
                // complete our single sign-out processing.
                string url = Url.Action("Logout", new { logoutId = vm.LogoutId });

                // this triggers a redirect to the external provider for sign-out
                return SignOut(new AuthenticationProperties { RedirectUri = url }, vm.ExternalAuthenticationScheme);
            }
            return Redirect(vm.PostLogoutRedirectUri ?? "/");
            //return View("LoggedOut", vm);
        }

        private async Task<LogoutViewModel> BuildLogoutViewModelAsync(string logoutId)
        {
            var vm = new LogoutViewModel { LogoutId = logoutId, ShowLogoutPrompt = AccountOptions.ShowLogoutPrompt };

            if (User?.Identity.IsAuthenticated != true)
            {
                // if the user is not authenticated, then just show logged out page
                vm.ShowLogoutPrompt = false;
                return vm;
            }

            var context = await _interaction.GetLogoutContextAsync(logoutId);
            if (context?.ShowSignoutPrompt == false)
            {
                // it's safe to automatically sign-out
                vm.ShowLogoutPrompt = false;
                return vm;
            }

            // show the logout prompt. this prevents attacks where the user
            // is automatically signed out by another malicious web page.
            return vm;
        }

        private async Task<LoggedOutViewModel> BuildLoggedOutViewModelAsync(string logoutId)
        {
            // get context information (client name, post logout redirect URI and iframe for federated signout)
            var logout = await _interaction.GetLogoutContextAsync(logoutId);

            var vm = new LoggedOutViewModel
            {
                AutomaticRedirectAfterSignOut = AccountOptions.AutomaticRedirectAfterSignOut,
                PostLogoutRedirectUri = logout?.PostLogoutRedirectUri,
                ClientName = string.IsNullOrEmpty(logout?.ClientName) ? logout?.ClientId : logout?.ClientName,
                SignOutIframeUrl = logout?.SignOutIFrameUrl,
                LogoutId = logoutId
            };

            if (User?.Identity.IsAuthenticated == true)
            {
                var idp = User.FindFirst(JwtClaimTypes.IdentityProvider)?.Value;
                if (idp != null && idp != IdentityServer4.IdentityServerConstants.LocalIdentityProvider)
                {
                    var providerSupportsSignout = await HttpContext.GetSchemeSupportsSignOutAsync(idp);
                    if (providerSupportsSignout)
                    {
                        if (vm.LogoutId == null)
                        {
                            // if there's no current logout context, we need to create one
                            // this captures necessary info from the current logged in user
                            // before we signout and redirect away to the external IdP for signout
                            vm.LogoutId = await _interaction.CreateLogoutContextAsync();
                        }

                        vm.ExternalAuthenticationScheme = idp;
                    }
                }
            }

            return vm;
        }

        private async Task<IActionResult> ProcessWindowsLoginAsync(string returnUrl)
        {
            // see if windows auth has already been requested and succeeded
            var result = await HttpContext.AuthenticateAsync(AccountOptions.WindowsAuthenticationSchemeName);
            if (result?.Principal is WindowsPrincipal wp)
            {
                // we will issue the external cookie and then redirect the
                // user back to the external callback, in essence, tresting windows
                // auth the same as any other external authentication mechanism
                var props = new AuthenticationProperties()
                {
                    RedirectUri = Url.Action("ExternalLoginCallback"),
                    Items =
                    {
                        { "returnUrl", returnUrl },
                        { "scheme", AccountOptions.WindowsAuthenticationSchemeName },
                    }
                };

                var id = new ClaimsIdentity(AccountOptions.WindowsAuthenticationSchemeName);
                id.AddClaim(new Claim(JwtClaimTypes.Subject, wp.Identity.Name));
                id.AddClaim(new Claim(JwtClaimTypes.Name, wp.Identity.Name));

                // add the groups as claims -- be careful if the number of groups is too large
                if (AccountOptions.IncludeWindowsGroups)
                {
                    var wi = wp.Identity as WindowsIdentity;
                    var groups = wi.Groups.Translate(typeof(NTAccount));
                    var roles = groups.Select(x => new Claim(JwtClaimTypes.Role, x.Value));
                    id.AddClaims(roles);
                }

                await HttpContext.SignInAsync(
                    IdentityServer4.IdentityServerConstants.ExternalCookieAuthenticationScheme,
                    new ClaimsPrincipal(id),
                    props);
                return Redirect(props.RedirectUri);
            }
            else
            {
                // trigger windows auth
                // since windows auth don't support the redirect uri,
                // this URL is re-triggered when we call challenge
                return Challenge(AccountOptions.WindowsAuthenticationSchemeName);
            }
        }

        //
        // POST: /Account/ExternalLogin
        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> ExternalLogin(string provider, string returnUrl = null)
        {
            if (AccountOptions.WindowsAuthenticationSchemeName == provider)
            {
                // windows authentication needs special handling
                return await ProcessWindowsLoginAsync(returnUrl);
            }
            else
            {
                // start challenge and roundtrip the return URL and 
                var props = new AuthenticationProperties()
                {
                    RedirectUri = Url.Action("ExternalLoginCallback"),
                    Items =
                    {
                        { "returnUrl", returnUrl },
                        { "scheme", provider },
                    }
                };
                return Challenge(props, provider);
            }
        }

        //
        // GET: /Account/ExternalLoginCallback
        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> ExternalLoginCallback()
        {
            // read external identity from the temporary cookie
            var result = await HttpContext.AuthenticateAsync(IdentityConstants.ExternalScheme);
            if (result.Succeeded)
            {
                // lookup our user and external provider info
                var (user, provider, providerUserId, claims) = await FindUserFromExternalProviderAsync(result);
                var returnUrl = result.Properties.Items["returnUrl"];

                if (user == null)
                {
                    // this might be where you might initiate a custom workflow for user registration
                    // in this sample we don't show how that would be done, as our sample implementation
                    // simply auto-provisions new external user
                    user = AutoProvisionUserAsync(provider, providerUserId, claims);

                    var existUser = _userManager.Users.FirstOrDefault(p => p.Email == user.Email);
                    if (existUser != null)
                    {
                        var re = await _userManager.AddLoginAsync(existUser, new UserLoginInfo(provider, providerUserId, provider));
                        if (re.Succeeded)
                        {
                            await _signInManager.SignInAsync(existUser, isPersistent: false);
                            var url = result.Properties.Items["returnUrl"];
                            if (_interaction.IsValidReturnUrl(url) || Url.IsLocalUrl(url))
                            {
                                return Redirect(url);
                            }
                            else
                                return RedirectToAction("Index", "Company");
                        }
                    }
                    return View("ExternalLoginConfirmation", new ExternalLoginConfirmationViewModel { Email = user.Email, Phone = user.PhoneNumber, FirstName = user.FirstName, LastName = user.LastName, ProviderUserId = providerUserId, Provider = provider });
                }
                else
                {
                    var link = new Uri(Environment.GetEnvironmentVariable("GATEWAY_API_URL") + returnUrl);
                    string companyId = HttpUtility.ParseQueryString(link.Query).Get("client_id");
                    bool exist = user.Companies.Contains(companyId);
                    if (!exist && !string.IsNullOrEmpty(companyId))
                    {
                        var company = _context.Company.AsQueryable().FirstOrDefault(p => p.Id == companyId);
                        ModelState.AddModelError("Username", _localizer.GetLocalizedHtmlString("usernameNotContainCompany") + " " + company.CompanyName);
                        return View("Login", await BuildLoginViewModelAsync(new LoginViewModel() { ReturnUrl = returnUrl, Username = user.UserName }));
                    }
                }

                // this allows us to collect any additonal claims or properties
                // for the specific prtotocols used and store them in the local auth cookie.
                // this is typically used to store data needed for signout from those protocols.
                var additionalLocalClaims = new List<Claim>();
                var localSignInProps = new AuthenticationProperties();
                ProcessLoginCallbackForOidc(result, additionalLocalClaims, localSignInProps);

                // issue authentication cookie for user
                // we must issue the cookie maually, and can't use the SignInManager because
                // it doesn't expose an API to issue additional claims from the login workflow
                var principal = await _signInManager.CreateUserPrincipalAsync(user);
                additionalLocalClaims.AddRange(principal.Claims);
                await _events.RaiseAsync(new UserLoginSuccessEvent(provider, providerUserId, user.Id.ToString(), user.UserName));
                await _signInManager.ExternalLoginSignInAsync(provider, providerUserId, isPersistent: false, bypassTwoFactor: true);
                await HttpContext.SignInAsync(user.Id.ToString(), user.UserName, provider, localSignInProps, additionalLocalClaims.ToArray());

                // delete temporary cookie used during external authentication
                //await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

                // validate return URL and redirect back to authorization endpoint or a local page
                //var returnUrl = result.Properties.Items["returnUrl"];
                if (_interaction.IsValidReturnUrl(returnUrl) || Url.IsLocalUrl(returnUrl))
                {
                    return Redirect(returnUrl);
                }
            }

            return RedirectToAction("Index", "Company");
        }

        private void ProcessLoginCallbackForOidc(AuthenticateResult externalResult, List<Claim> localClaims, AuthenticationProperties localSignInProps)
        {
            // if the external system sent a session id claim, copy it over
            // so we can use it for single sign-out
            var sid = externalResult.Principal.Claims.FirstOrDefault(x => x.Type == JwtClaimTypes.SessionId);
            if (sid != null)
            {
                localClaims.Add(new Claim(JwtClaimTypes.SessionId, sid.Value));
            }

            // if the external provider issued an id_token, we'll keep it for signout
            var id_token = externalResult.Properties.GetTokenValue("id_token");
            if (id_token != null)
            {
                localSignInProps.StoreTokens(new[] { new AuthenticationToken { Name = "id_token", Value = id_token } });
            }
        }

        private ApplicationUser AutoProvisionUserAsync(string provider, string providerUserId, IEnumerable<Claim> claims)
        {
            // create a list of claims that we want to transfer into our store
            var filtered = new List<Claim>();

            // user's display name
            var name = claims.FirstOrDefault(x => x.Type == JwtClaimTypes.Name)?.Value ??
                claims.FirstOrDefault(x => x.Type == ClaimTypes.Name)?.Value;
            if (name != null)
            {
                filtered.Add(new Claim(JwtClaimTypes.Name, name));
            }
            else
            {
                var first = claims.FirstOrDefault(x => x.Type == JwtClaimTypes.GivenName)?.Value ??
                    claims.FirstOrDefault(x => x.Type == ClaimTypes.GivenName)?.Value;
                var last = claims.FirstOrDefault(x => x.Type == JwtClaimTypes.FamilyName)?.Value ??
                    claims.FirstOrDefault(x => x.Type == ClaimTypes.Surname)?.Value;
                if (first != null && last != null)
                {
                    filtered.Add(new Claim(JwtClaimTypes.Name, first + " " + last));
                }
                else if (first != null)
                {
                    filtered.Add(new Claim(JwtClaimTypes.Name, first));
                }
                else if (last != null)
                {
                    filtered.Add(new Claim(JwtClaimTypes.Name, last));
                }
            }

            // email
            var email = claims.FirstOrDefault(x => x.Type == JwtClaimTypes.Email)?.Value ??
               claims.FirstOrDefault(x => x.Type == ClaimTypes.Email)?.Value;
            if (email != null)
            {
                filtered.Add(new Claim(JwtClaimTypes.Email, email));
            }

            var user = new ApplicationUser
            {
                UserName = email ?? Guid.NewGuid().ToString(),
                Email = email ?? ""
            };
            //var identityResult = await _userManager.CreateAsync(user); 
            //if (identityResult.Succeeded)
            //{
            //    if (filtered.Any())
            //    {
            //        identityResult = await _userManager.AddClaimsAsync(user, filtered);
            //        if (identityResult.Succeeded)
            //        {
            //            identityResult = await _userManager.AddLoginAsync(user, new UserLoginInfo(provider, providerUserId, provider));
            //        }
            //    }
            //}

            return user;
        }

        private async Task<(ApplicationUser user, string provider, string providerUserId, IEnumerable<Claim> claims)>
            FindUserFromExternalProviderAsync(AuthenticateResult result)
        {
            var externalUser = result.Principal;

            // try to determine the unique id of the external user (issued by the provider)
            // the most common claim type for that are the sub claim and the NameIdentifier
            // depending on the external provider, some other claim type might be used
            var userIdClaim = externalUser.FindFirst(JwtClaimTypes.Subject) ??
                              externalUser.FindFirst(ClaimTypes.NameIdentifier) ??
                              throw new Exception("Unknown userid");

            // remove the user id claim so we don't include it as an extra claim if/when we provision the user
            var claims = externalUser.Claims.ToList();
            claims.Remove(userIdClaim);

            var provider = result.Properties.Items["scheme"];
            var providerUserId = userIdClaim.Value;

            // find external user
            var user = await _userManager.FindByLoginAsync(provider, providerUserId);

            return (user, provider, providerUserId, claims);
        }

        //
        // POST: /Account/ExternalLoginConfirmation
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ExternalLoginConfirmation(ExternalLoginConfirmationViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = new ApplicationUser { UserName = model.Email, Email = model.Email, FirstName = model.FirstName, LastName = model.LastName, PhoneNumber = model.Phone, IsActive = true, CreatedAt = DateTime.Now };
                var result = await _userManager.CreateAsync(user);
                if (result.Succeeded)
                {
                    user = await _userManager.FindByIdAsync(user.Id);
                    var resultA = await _userManager.AddLoginAsync(user, new UserLoginInfo(model.Provider, model.ProviderUserId, model.Provider));
                    if (resultA.Succeeded)
                    {
                        await _signInManager.SignInAsync(user, isPersistent: false);
                        return RedirectToAction("Index", "Company");
                    }
                }
            }

            return View(model);
        }

        // GET: /Account/ConfirmEmail
        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> ConfirmEmail(string userId, string code)
        {
            if (userId == null || code == null)
            {
                return View("Error");
            }
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return View("Error");
            }
            var result = await _userManager.ConfirmEmailAsync(user, code);
            return View(result.Succeeded ? "ConfirmEmail" : "Error");
        }

        //
        // GET: /Account/ForgotPassword 
        [HttpGet]
        [AllowAnonymous]
        public IActionResult ForgotPassword(string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        //
        // POST: /Account/ForgotPassword
        [HttpPost]
        [AllowAnonymous]
        //[ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model, string returnUrl = null)
        {
            if (ModelState.IsValid)
            {
                var user = _userManager.Users.Where(s => s.UserName == model.Username || s.Email == model.Username || s.PhoneNumber == model.Username).FirstOrDefault();
                if (user == null)
                {
                    // Don't reveal that the user does not exist or is not confirmed
                    return RedirectToAction("ForgotPasswordConfirmation", new { ReturnUrl = returnUrl });
                }

                // For more information on how to enable account confirmation and password reset please
                // visit https://go.microsoft.com/fwlink/?LinkID=532713
                var code = await _userManager.GeneratePasswordResetTokenAsync(user);
                var callbackUrl = Url.ResetPasswordCallbackLink(user.Id, code, Request.Scheme);
                await _publishEndpoint.Publish<ISendMail>(
                        new
                        {
                            TypeNotification = TypeNotification.ForgotPassword,
                            Culture = System.Globalization.CultureInfo.CurrentCulture.Name,
                            ObjectId = user.Id,
                            ObjectType = "users",
                            Data = new DataSendMail()
                            {
                                Receiver = user.Email,
                                Body = callbackUrl
                            }
                        });
                //send mail here
                return RedirectToAction("ForgotPasswordConfirmation", new { ReturnUrl = returnUrl });
            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }

        //
        // GET: /Account/ForgotPasswordConfirmation
        [HttpGet]
        [AllowAnonymous]
        public IActionResult ForgotPasswordConfirmation(string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        //
        // GET: /Account/ResetPassword
        [HttpGet]
        [AllowAnonymous]
        public IActionResult ResetPassword(string userId = null, string code = null)
        {
            return userId == null || code == null ? View("Error") : View();
        }

        //
        // GET: /Account/ChangePassword
        [HttpGet]
        [AllowAnonymous]
        public IActionResult ChangePassword()
        {
            return View();
        }

        //
        // POST: /Account/ResetPassword
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(Models.AccountViewModels.ResetPasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }
            var user = await _userManager.FindByIdAsync(model.UserId);
            if (user == null)
            {
                // Don't reveal that the user does not exist
                return RedirectToAction(nameof(AccountController.ResetPasswordConfirmation), "Account");
            }
            var result = await _userManager.ResetPasswordAsync(user, model.Code, model.Password);
            if (result.Succeeded)
            {
                return RedirectToAction(nameof(AccountController.ResetPasswordConfirmation), "Account");
            }
            AddErrors(result);
            return View();
        }

        //
        // POST: /Account/ResetPasswordUser
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ChangePassword(Models.ManageViewModels.ChangePasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }
            var currentuser = await _userManager.GetUserAsync(User);
            var result = await _userManager.ChangePasswordAsync(currentuser, model.OldPassword, model.NewPassword);
            if (result.Succeeded)
            {
                var user = await _userManager.FindByIdAsync(currentuser.Id);
                if (user != null)
                {
                    await _signInManager.SignInAsync(user, isPersistent: false);

                }
                return RedirectToAction("Index", "Company");
            }
            AddErrors(result);
            return View(model);
        }

        //
        // GET: /Account/ResetPasswordConfirmation
        [HttpGet]
        [AllowAnonymous]
        public IActionResult ResetPasswordConfirmation()
        {
            return View();
        }

        #region Helpers

        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
        }

        private IActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            else
            {
                return new EmptyResult();
                //return RedirectToAction(nameof(HomeController.Index), "Home");
            }
        }

        #endregion
    }
}
