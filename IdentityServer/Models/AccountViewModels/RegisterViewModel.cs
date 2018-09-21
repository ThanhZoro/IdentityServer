using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace IdentityServer.Models.AccountViewModels
{
    public class RegisterViewModel
    {
        [Required(ErrorMessage = "usernameRequired")]
        [EmailAddress(ErrorMessage = "emailInvalid")]
        [Display(Name = "UserName")]
        public string UserName { get; set; }

        [Required(ErrorMessage = "phoneRequired")]
        [Phone(ErrorMessage = "phoneInvalid")]
        [Display(Name = "Phone")]
        public string Phone { get; set; }

        [StringLength(255)]
        [Required(ErrorMessage = "firstNameRequired")]
        [Display(Name = "FirstName")]
        public string FirstName { get; set; }

        [StringLength(255)]
        [Display(Name = "LastName")]
        public string LastName { get; set; }

        [Required(ErrorMessage = "passwordRequired")]
        [StringLength(100, ErrorMessage = "lengthRequired", MinimumLength = 6)]
        [DataType(DataType.Password)]
        [Display(Name = "Password")]
        [RegularExpression(@"^(.).*?((?!\1).).*?((?!\1|\2).).*?((?!\1|\2|\3).).*?((?!\1|\2|\3|\4).).*?$", ErrorMessage = "uniqueCharacters")]
        public string Password { get; set; }
    }
}
