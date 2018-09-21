using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityServer.Models.AccountViewModels
{
    public class ExternalLoginConfirmationViewModel
    {
        [Required(ErrorMessage = "phoneRequired")]
        [Display(Name = "Phone")]
        public string Phone { get; set; }
        [Required(ErrorMessage = "emailRequired")]
        [EmailAddress]
        public string Email { get; set; }

        [StringLength(255)]
        [Required(ErrorMessage = "firstNameRequired")]
        [Display(Name = "FirstName")]
        public string FirstName { get; set; }

        [StringLength(255)]
        [Display(Name = "LastName")]
        public string LastName { get; set; }
        public string Provider { get; set; }
        public string ProviderUserId { get; set; }
    }
}
