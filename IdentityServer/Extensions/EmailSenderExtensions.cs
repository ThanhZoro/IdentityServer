using IdentityServer.Services;
using System;
using System.Globalization;
using System.IO;
using System.Threading.Tasks;

namespace IdentityServer.Extensions
{
    public static class EmailSenderExtensions
    {
        public static async Task SendEmailConfirmationAsync(this IEmailSender emailSender, string email, string code)
        {
            string body = string.Empty;
            string subject = string.Empty;
            string link = $"./EmailTemplates/ActiveAccount-{CultureInfo.CurrentCulture.Name ?? "vi-VN"}.html";
            switch (CultureInfo.CurrentCulture.Name)
            {
                case "vi-VN":
                    subject = "Mã kích hoạt tài khoản";
                    break;
                case "en-US":
                    subject = "Account activation code";
                    break;
                default:
                    subject = "Mã kích hoạt tài khoản";
                    break;
            }
            using (StreamReader reader = File.OpenText(link))
            {
                body = reader.ReadToEnd();
            }
            using (StreamReader reader = File.OpenText(link))
            {
                body = reader.ReadToEnd();
            }
            body = body.Replace("{OTPNumber}", code);
            await emailSender.SendEmailAsync(email, subject, body);
        }

        public static async Task SendEmailForgotPasswordAsync(this IEmailSender emailSender, string email, string callbackUrl)
        {
            string body = string.Empty;
            string link = $"./EmailTemplates/ForgotPassword-{CultureInfo.CurrentCulture.Name ?? "vi-VN"}.html";
            string subject = string.Empty;
            switch (CultureInfo.CurrentCulture.Name)
            {
                case "vi-VN":
                    subject = "Đặt lại mật khấu";
                    break;
                case "en-US":
                    subject = "Account reset your password";
                    break;
                default:
                    subject = "Đặt lại mật khấu";
                    break;
            }
            using (StreamReader reader = File.OpenText(link))
            {
                body = reader.ReadToEnd();
            }
            body = body.Replace("{callbackUrl}", callbackUrl);
            await emailSender.SendEmailAsync(email, subject, body);
        }

        public static async Task SendEmailRegistrationAsync(this IEmailSender emailSender, string email, string userId, string culture)
        {
            string body = string.Empty;
            string link = $"./EmailTemplates/RegisterAccount-{CultureInfo.CurrentCulture.Name ?? "vi-VN"}.html";
            string subject = string.Empty;
            switch (culture)
            {
                case "vi-VN":
                    subject = "Chúc mừng bạn đã đăng ký tài khoản thành công";
                    break;
                case "en-US":
                    subject = "Congratulations for successful registration account";
                    break;
                default:
                    subject = "Chúc mừng bạn đã đăng ký tài khoản thành công";
                    break;
            }
            using (StreamReader reader = File.OpenText(link))
            {
                body = reader.ReadToEnd();
            }
            await emailSender.SendEmailAsync(email, subject, body);
        }
    }
}

