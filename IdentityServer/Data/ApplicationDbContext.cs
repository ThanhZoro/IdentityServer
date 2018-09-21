using Contracts.Models;
using IdentityServer.Models;
using Microsoft.Extensions.Options;
using MongoDB.Driver;

namespace IdentityServer.Data
{
    public class ApplicationDbContext
    {
        private readonly IMongoDatabase _database = null;

        public ApplicationDbContext(IOptions<MongoDBSettings> settings)
        {
            var client = new MongoClient(settings.Value.ConnectionString);
            if (client != null)
                _database = client.GetDatabase(settings.Value.Database);
        }

        public IMongoCollection<Company> Company
        {
            get
            {
                return _database.GetCollection<Company>("company");
            }
        }
    }
}
