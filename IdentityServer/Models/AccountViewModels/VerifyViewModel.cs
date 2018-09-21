using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityServer.Models.AccountViewModels
{
    public class VerifyAccountViewModel
    {
        public string Phone { get; set; }
        public string Email { get; set; }
        [Required]
        public string VerifyType { get; set; }
    }

    public class VerifyViewModel
    {
        [Required]
        public string VerifyType { get; set; }
        [Required]
        public string Code { get; set; }
        public long CountSendNotification { get; set; }

    }
}
