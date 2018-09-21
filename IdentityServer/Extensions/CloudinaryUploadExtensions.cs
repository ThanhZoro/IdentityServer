using CloudinaryDotNet;
using CloudinaryDotNet.Actions;
using Microsoft.AspNetCore.Http;

namespace IdentityServer.Extensions
{
    public static class CloudinaryUploadExtensions
    {
        public static ImageUploadResult UploadImageCompany(this IFormFile file)
        {
            Account account = new Account();
            Cloudinary cloudinary = new Cloudinary(account);
            var uploadParams = new ImageUploadParams()
            {
                File = new FileDescription(file.FileName, file.OpenReadStream()),
                Transformation = new Transformation().Crop("limit").Width(200).Height(200)
            };
            var uploadResult = cloudinary.Upload(uploadParams);
            return uploadResult;
        }
    }
}
