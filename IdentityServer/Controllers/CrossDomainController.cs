using Microsoft.AspNetCore.Mvc;

namespace IdentityServer.Controllers
{
    public class CrossDomainController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
    }
}