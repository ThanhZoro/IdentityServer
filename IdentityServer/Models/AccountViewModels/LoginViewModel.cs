﻿using System;
using System.Collections.Generic;
using System.Linq;

namespace IdentityServer.Models
{
    public class LoginViewModel : LoginInputModel
    {
        public bool AllowRememberLogin { get; set; }
        public bool EnableLocalLogin { get; set; }
        public IEnumerable<ExternalProvider> ExternalProviders { get; set; }
        public IEnumerable<ExternalProvider> VisibleExternalProviders => ExternalProviders.Where(x => !String.IsNullOrWhiteSpace(x.DisplayName));

        public bool IsExternalLoginOnly => !EnableLocalLogin && ExternalProviders?.Count() == 1;
        public string ExternalLoginScheme => IsExternalLoginOnly ? ExternalProviders?.SingleOrDefault()?.AuthenticationScheme : null;
        public string LogoUrl { get; set; } = "";
        public string CompanyName { get; set; } = "";
    }

    public class ExternalProvider
    {
        public string DisplayName { get; set; }
        public string AuthenticationScheme { get; set; }
    }
}