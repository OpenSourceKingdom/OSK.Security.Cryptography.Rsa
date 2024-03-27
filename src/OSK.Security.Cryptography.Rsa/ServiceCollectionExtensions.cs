using Microsoft.Extensions.DependencyInjection;
using OSK.Security.Cryptography.Rsa.Internal.Services;
using OSK.Security.Cryptography.Rsa.Models;

namespace OSK.Security.Cryptography.Rsa
{
    public static class ServiceCollectionExtensions
    {
        public static IServiceCollection AddRsaKeyService(this IServiceCollection services)
        {
            services.AddAsymmetricKeyService<RsaKeyService, RsaKeyInformation>();

            return services;
        }
    }
}
