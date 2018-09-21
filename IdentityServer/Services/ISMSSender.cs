using System.Threading.Tasks;
using static IdentityServer.Services.SMSSender;

namespace IdentityServer.Services
{
    public interface ISMSSender
    {
        Task<ApiBulkReturn> SendSMSAsync(string phone, string message);
    }
}
