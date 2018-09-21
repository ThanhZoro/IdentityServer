using Newtonsoft.Json;
using System;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Serialization;

namespace IdentityServer.Services
{
    public class SMSSender : ISMSSender
    {
        private static string APISMS_VMG_URL = "http://brandsms.vn:8018";
        private static string APISMS_VMG_USER_NAME = Environment.GetEnvironmentVariable("APISMS_VMG_USER_NAME");
        private static string APISMS_VMG_PASSWORD = Environment.GetEnvironmentVariable("APISMS_VMG_PASSWORD");
        private static string APISMS_VMG_ALIAS = Environment.GetEnvironmentVariable("APISMS_VMG_ALIAS");
        private static string APISMS_VMG_PREFIX = Environment.GetEnvironmentVariable("APISMS_VMG_PREFIX");

        public Task<ApiBulkReturn> SendSMSAsync(string phone, string message)
        {
            ApiBulkReturn data = new ApiBulkReturn();
            var xml = Execute(phone, message);
            var xmlSerializer = new XmlSerializer(typeof(ApiBulkReturn));
            using (StringReader reader = new StringReader(xml.Result))
            {
                data = (ApiBulkReturn)xmlSerializer.Deserialize(reader);
                return Task.FromResult(data);
            }
        }

        public Task<string> Execute(string phone, string message)
        {
            string sendTime = DateTime.Now.ToString("dd/MM/yyyy");
            try
            {
                phone = APISMS_VMG_PREFIX + phone.Substring(1);
                var postData = "msisdn=" + phone + "&alias=" + APISMS_VMG_ALIAS + "&message=" + message +
                               "&sendTime=" + sendTime + "&authenticateUser=" + APISMS_VMG_USER_NAME +
                               "&authenticatePass=" + DecryptString(APISMS_VMG_PASSWORD);

                string url = APISMS_VMG_URL + @"/VMGAPI.asmx/BulkSendSms?" + postData;

                HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
                request.AutomaticDecompression = DecompressionMethods.GZip;

                HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                Stream stream = response.GetResponseStream();
                StreamReader reader = new StreamReader(stream);
                return Task.FromResult(reader.ReadToEnd());
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
        }


        [XmlRoot(ElementName = "ApiBulkReturn", Namespace = "http://tempuri.org/")]
        public class ApiBulkReturn
        {
            [XmlElement("error_code")]
            [JsonProperty("error_code")]
            public string error_code { get; set; }

            [XmlElement("error_detail")]
            [JsonProperty("error_detail")]
            public string error_detail { get; set; }

            [XmlElement("messageId")]
            [JsonProperty("messageId")]
            public string messageId { get; set; }
        }

        public static string DecryptString(string cipherText)
        {
            var fullCipher = Convert.FromBase64String(cipherText);

            var iv = new byte[16];
            var cipher = new byte[16];

            Buffer.BlockCopy(fullCipher, 0, iv, 0, iv.Length);
            Buffer.BlockCopy(fullCipher, iv.Length, cipher, 0, iv.Length);
            var key = Encoding.UTF8.GetBytes("E546C8DF278CD5931069B522E695D4F2");

            using (var aesAlg = Aes.Create())
            {
                using (var decryptor = aesAlg.CreateDecryptor(key, iv))
                {
                    string result;
                    using (var msDecrypt = new MemoryStream(cipher))
                    {
                        using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                        {
                            using (var srDecrypt = new StreamReader(csDecrypt))
                            {
                                result = srDecrypt.ReadToEnd();
                            }
                        }
                    }

                    return result;
                }
            }
        }
    }
}

