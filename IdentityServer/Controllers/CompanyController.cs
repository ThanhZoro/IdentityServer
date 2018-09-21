using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using IdentityServer4;
using IdentityServer4.Models;
using IdentityServer4.MongoDB.Interfaces;
using IdentityServer4.MongoDB.Mappers;
using IdentityServer.CultureResources;
using IdentityServer.Data;
using IdentityServer.Models;
using MassTransit;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using MongoDB.Driver;
using IdentityServer.Extensions;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Contracts.Commands;
using Contracts.Models;

namespace IdentityServer.Controllers
{
    [Authorize]
    [Route("[controller]/[action]")]
    public class CompanyController : Controller
    {
        protected ApplicationDbContext _context;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IServiceScopeFactory _scopeFactory;
        private readonly LocService _localizer;
        private readonly IRequestClient<ICreateCompany, Company> _createCompanyRequestClient;
        private readonly IRequestClient<IUploadLogoCompany, Company> _uploadLogoCompanyRequestClient;
        public CompanyController(
            UserManager<ApplicationUser> userManager,
            IOptions<MongoDBSettings> settings,
            IServiceScopeFactory scopeFactory,
            LocService localizer,
            IRequestClient<ICreateCompany, Company> createCompanyRequestClient,
            IRequestClient<IUploadLogoCompany, Company> uploadLogoCompanyRequestClient)
        {
            _userManager = userManager;
            _context = new ApplicationDbContext(settings);
            _scopeFactory = scopeFactory;
            _localizer = localizer;
            _createCompanyRequestClient = createCompanyRequestClient;
            _uploadLogoCompanyRequestClient = uploadLogoCompanyRequestClient;
        }

        // GET: Company
        public async Task<IActionResult> Index()
        {
            var currentUser = await _userManager.GetUserAsync(User);
            if (!currentUser.IsActive)
            {
                return RedirectToAction("Index", "Home");
            }
            var listCompany = new List<Company>();
            if (currentUser.Companies != null)
            {
                listCompany = _context.Company.AsQueryable().Where(s => currentUser.Companies.Contains(s.Id)).ToList();
            }

            return View(listCompany);
        }

        // GET: Company/Create
        public async Task<IActionResult> Create()
        {
            var currentUser = await _userManager.GetUserAsync(User);
            if (!currentUser.IsActive)
            {
                return RedirectToAction("Index", "Home");
            }
            return View(new CreateCompany());
        }

        // POST: Company/Create
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(CreateCompany company)
        {
            if (ModelState.IsValid)
            {
                var existCode = await _context.Company.Find(_ => _.CompanyCode == company.CompanyCode).FirstOrDefaultAsync();
                if (existCode == null)
                {
                    var currentUser = await _userManager.GetUserAsync(User);
                    company.OwnerId = currentUser.Id;
                    company.CreatedBy = currentUser.UserName;
                    company.Culture = System.Globalization.CultureInfo.CurrentCulture.Name.Split('-')[0];
                    company.LanguageDefault = System.Globalization.CultureInfo.CurrentCulture.Name; ;

                    var appDomain = Environment.GetEnvironmentVariable("APP_DOMAIN");

                    //await _context.Company.InsertOneAsync(company);
                    var result = await _createCompanyRequestClient.Request(company);
                    currentUser.Companies.Add(result.Id);
                    await _userManager.UpdateAsync(currentUser);
                    using (var scope = _scopeFactory.CreateScope())
                    {
                        var context = scope.ServiceProvider.GetRequiredService<IConfigurationDbContext>();

                        var client = new Client
                        {
                            ClientId = result.Id,
                            ClientName = $"{result.CompanyName} Application",
                            RequireConsent = false,
                            AllowedGrantTypes = GrantTypes.Implicit,
                            AllowAccessTokensViaBrowser = true,
                            RequireClientSecret = false,
                            AccessTokenType = AccessTokenType.Jwt,

                            RedirectUris =
                            {
                                //http
                                $"http://{result.CompanyCode}.{appDomain}",
                                $"http://{result.CompanyCode}.{appDomain}/callback.html",
                                $"http://{result.CompanyCode}.{appDomain}/silent.html",
                                $"http://{result.CompanyCode}.{appDomain}/popup.html",
                                //https
                                $"https://{result.CompanyCode}.{appDomain}",
                                $"https://{result.CompanyCode}.{appDomain}/callback.html",
                                $"https://{result.CompanyCode}.{appDomain}/silent.html",
                                $"https://{result.CompanyCode}.{appDomain}/popup.html"
                            },

                            PostLogoutRedirectUris = {
                                $"http://{result.CompanyCode}.{appDomain}",
                                $"https://{result.CompanyCode}.{appDomain}"
                            },
                            AllowedCorsOrigins = {
                                $"http://{result.CompanyCode}.{appDomain}",
                                $"https://{result.CompanyCode}.{appDomain}"
                            },
                            AllowedScopes =
                            {
                                IdentityServerConstants.StandardScopes.OpenId,
                                IdentityServerConstants.StandardScopes.Profile,
                                IdentityServerConstants.StandardScopes.Email,
                                "api", "api2.read_only", "api2.full_access"
                            }
                        };
                        await context.AddClient(client.ToEntity());
                    }

                    return RedirectToAction("UploadLogo", new { result.Id });
                }
                else
                {
                    ModelState.AddModelError("CompanyCode", _localizer.GetLocalizedHtmlString("companyCodeExisted"));
                }
            }
            return View(company);
        }

        [HttpGet]
        public async Task<IActionResult> UploadLogo(string id)
        {
            try
            {
                var currentUser = await _userManager.GetUserAsync(User);
                if (!currentUser.IsActive)
                {
                    return RedirectToAction("Index", "Home");
                }
                var appDomain = Environment.GetEnvironmentVariable("APP_DOMAIN");
                var company = await _context.Company.Find(_ => _.Id == id).FirstOrDefaultAsync();
                if (company != null)
                {
                    return View("CreateCompanySuccess", new CreateCompanySuccess { AppDomain = $"http://{company.CompanyCode}.{appDomain}", CompanyId = company.Id });
                }
                return View("Error");
            }
            catch (Exception)
            {
                return View("Error");
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> CreateCompanySuccess(CreateCompanySuccess model)
        {
            if (ModelState.IsValid)
            {
                var uploadResult = CloudinaryUploadExtensions.UploadImageCompany(model.FileUrl);
                var company = await _uploadLogoCompanyRequestClient.Request(new { Id = model.CompanyId, LogoUrl = uploadResult.Uri.OriginalString, UpdatedBy = User.Identity.Name });
            }
            return Redirect(model.AppDomain);
        }
    }
}