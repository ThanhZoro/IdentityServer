using Microsoft.AspNetCore.Http;
using System.ComponentModel.DataAnnotations;

namespace IdentityServer.Models
{
    public class CreateCompanySuccess
    {
        [Required]
        public string AppDomain { get; set; }
        [Required]
        public string CompanyId { get; set; }
        [Required]
        public IFormFile FileUrl { get; set; }
    }
}
