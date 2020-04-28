using Arcus.Security.Providers.AzureKeyVault;
using Arcus.Security.Providers.AzureKeyVault.Authentication;
using Arcus.Security.Providers.AzureKeyVault.Configuration;
using Microsoft.Extensions.Hosting;

namespace Arcus.Security.Startup.Security 
{
    public static class SecretStoreBuilderExtensions
    {
        public static SecretStoreBuilder AddAzureKeyVaultProvider(this SecretStoreBuilder builder, IKeyVaultAuthentication authentication, IKeyVaultConfiguration configuration)
        {
            return builder.AddProvider(new KeyVaultSecretProvider(authentication, configuration));
        }

        public static SecretStoreBuilder AddEnvironmentVariableProvider(this SecretStoreBuilder builder)
        {
            return builder.AddProvider(new EnvironmentVariableSecretProvider());
        }
    }
}
