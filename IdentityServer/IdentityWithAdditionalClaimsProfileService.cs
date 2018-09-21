using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using IdentityServer.Models;
using IdentityModel;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Services;
using Microsoft.AspNetCore.Identity;
using IdentityServer.Data;
using Microsoft.Extensions.Options;
using MongoDB.Driver;
using Contracts.Models;

namespace IdentityServer
{
    public class IdentityWithAdditionalClaimsProfileService : IProfileService
    {
        private readonly IUserClaimsPrincipalFactory<ApplicationUser> _claimsFactory;
        private readonly UserManager<ApplicationUser> _userManager;
        protected ApplicationDbContext _context;

        public IdentityWithAdditionalClaimsProfileService(UserManager<ApplicationUser> userManager, IUserClaimsPrincipalFactory<ApplicationUser> claimsFactory, IOptions<MongoDBSettings> settings)
        {
            _userManager = userManager;
            _claimsFactory = claimsFactory;
            _context = new ApplicationDbContext(settings);
        }

        public async Task GetProfileDataAsync(ProfileDataRequestContext context)
        {
            var sub = context.Subject.GetSubjectId();
            var user = await _userManager.FindByIdAsync(sub);

            var principal = await _claimsFactory.CreateAsync(user);
            var claims = principal.Claims.ToList();
            claims = claims.Where(claim => context.RequestedClaimTypes.Contains(claim.Type)).ToList();
            claims.Add(new Claim(JwtClaimTypes.GivenName, user.UserName));
            claims.Add(new Claim("userName", user.UserName));
            claims.Add(new Claim("firstName", user.FirstName));
            claims.Add(new Claim("lastName", user.LastName ?? ""));
            claims.Add(new Claim("phone", user.PhoneNumber));
            claims.Add(new Claim("email", user.Email));
            claims.Add(new Claim("avatarUrl", user.AvatarUrl ?? ""));
            claims.Add(new Claim("requiredChangePassword", user.RequiredChangePassword.ToString()));

            if (user.Companies != null && user.Companies.Count > 0)
            {
                foreach (var item in user.Companies)
                {
                    claims.Add(new Claim("companies", item ?? ""));
                }
            }

            context.IssuedClaims = claims;
        }

        public async Task IsActiveAsync(IsActiveContext context)
        {
            var sub = context.Subject.GetSubjectId();
            var user = await _userManager.FindByIdAsync(sub);
            var userInCompany = user.Companies.Contains(context.Client.ClientId);
            context.IsActive = user != null && user.IsActive && userInCompany;
        }
    }
}