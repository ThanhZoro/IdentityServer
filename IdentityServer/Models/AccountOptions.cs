using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityServer.Models
{
    public static class AccountOptions
    {
        private static bool allowLocalLogin = true;
        private static bool allowRememberLogin = true;
        private static TimeSpan rememberMeLoginDuration = TimeSpan.FromDays(30);

        private static bool showLogoutPrompt = false;
        private static bool automaticRedirectAfterSignOut = true;

        // specify the Windows authentication scheme being used
        public static readonly string WindowsAuthenticationSchemeName = Microsoft.AspNetCore.Server.IISIntegration.IISDefaults.AuthenticationScheme;
        // if user uses windows auth, should we load the groups from windows
        private static bool includeWindowsGroups = false;

        private static string invalidCredentialsErrorMessage = "Invalid username or password";

        public static bool AllowLocalLogin { get => allowLocalLogin; set => allowLocalLogin = value; }
        public static bool AllowRememberLogin { get => allowRememberLogin; set => allowRememberLogin = value; }
        public static TimeSpan RememberMeLoginDuration { get => rememberMeLoginDuration; set => rememberMeLoginDuration = value; }
        public static bool ShowLogoutPrompt { get => showLogoutPrompt; set => showLogoutPrompt = value; }
        public static bool AutomaticRedirectAfterSignOut { get => automaticRedirectAfterSignOut; set => automaticRedirectAfterSignOut = value; }
        public static bool IncludeWindowsGroups { get => includeWindowsGroups; set => includeWindowsGroups = value; }
        public static string InvalidCredentialsErrorMessage { get => invalidCredentialsErrorMessage; set => invalidCredentialsErrorMessage = value; }
    }
}
