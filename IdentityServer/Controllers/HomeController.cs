using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using IdentityServer.Models;
using IdentityServer4.Services;
using IdentityServer.CultureResources;

namespace IdentityServer.Controllers
{
    public class HomeController : Controller
    {
        private readonly IIdentityServerInteractionService _interaction;
        private readonly LocService _localizer;
        public HomeController(LocService localizer, IIdentityServerInteractionService interaction)
        {
            _interaction = interaction;
            _localizer = localizer;
        }
        public IActionResult Index()
        {
            return View();
        }

        public async Task<IActionResult> Error(string errorId)
        {
            var vm = new ErrorViewModel();

            // retrieve error details from identityserver
            var message = await _interaction.GetErrorContextAsync(errorId);
            if (message != null)
            {
                vm.Error = message;
            }

            return View("Error", vm);
        }
    }
}
