using Contracts.Commands;
using System.ComponentModel.DataAnnotations;

namespace IdentityServer.Models
{
    public class CreateCompany : ICreateCompany
    {
        public string Culture { get; set; }
        [RegularExpression("^[a-zA-Z0-9]*$", ErrorMessage = "Only Alphabets and Numbers allowed.")]
        [Display(Name = "CompanyCode")]
        [Required(ErrorMessage = "companyCodeRequired")]
        public string CompanyCode { get; set; }
        public string CompanyType { get; set; }
        [Required(ErrorMessage = "companyNameRequired")]
        [Display(Name = "CompanyName")]
        public string CompanyName { get; set; }
        [Display(Name = "CompanyWebsite")]
        public string CompanyWebsite { get; set; }
        [Display(Name = "CompanyAddress")]
        public string CompanyAddress { get; set; }
        [Phone(ErrorMessage = "phoneInvalid")]
        public string Phone { get; set; }
        public string Fax { get; set; }
        [EmailAddress(ErrorMessage = "emailInvalid")]
        public string Email { get; set; }
        public string TaxCode { get; set; }
        public string ScaleId { get; set; }
        public string OwnerId { get; set; }
        public string CreatedBy { get; set; }
        public string LanguageDefault { get; set; }
    }
}
