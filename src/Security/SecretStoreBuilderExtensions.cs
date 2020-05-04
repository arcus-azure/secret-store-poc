using System.Collections;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using Arcus.Security.Core;
using Arcus.Security.Providers.AzureKeyVault;
using Arcus.Security.Providers.AzureKeyVault.Authentication;
using Arcus.Security.Providers.AzureKeyVault.Configuration;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;

namespace Arcus.Security.Startup.Security
{
    public static class SecretStoreBuilderExtensions
    {
        public static SecretStoreBuilder AddAzureKeyVault(
            this SecretStoreBuilder builder,
            IKeyVaultAuthentication authentication,
            IKeyVaultConfiguration configuration)
        {
            return builder.AddProvider(new KeyVaultSecretProvider(authentication, configuration));
        }

        public static SecretStoreBuilder AddAzureKeyVaultWithCertificate(
            this SecretStoreBuilder builder,
            string rawVaultUri,
            string clientId,
            X509Certificate2 certificate)
        {
            return AddAzureKeyVault(
                builder,
                new CertificateBasedAuthentication(clientId, certificate),
                new KeyVaultConfiguration(rawVaultUri));
        }

        public static SecretStoreBuilder AddAzureKeyVaultWithManagedServiceIdentity(
            this SecretStoreBuilder builder,
            string rawVaultUri,
            string connectionString = null,
            string azureADInstance = null)
        {
            return AddAzureKeyVault(
                builder,
                new ManagedServiceIdentityAuthentication(connectionString, azureADInstance),
                new KeyVaultConfiguration(rawVaultUri));
        }

        public static SecretStoreBuilder AddAzureKeyVaultWithServicePrincipal(
            this SecretStoreBuilder builder,
            string rawVaultUri,
            string clientId,
            string clientKey)
        {
            return AddAzureKeyVault(
                builder,
                new ServicePrincipalAuthentication(clientId, clientKey),
                new KeyVaultConfiguration(rawVaultUri));
        }

        public static SecretStoreBuilder AddEnvironmentVariables(this SecretStoreBuilder builder)
        {
            return builder.AddProvider(new EnvironmentVariableSecretProvider());
        }

        public static SecretStoreBuilder AddInMemory(
            this SecretStoreBuilder builder,
            IDictionary<string, Secret> secrets)
        {
            var provider = new InMemorySecretProvider(secrets);
            return builder.AddProvider(provider);
        }

        public static SecretStoreBuilder AddConfiguration(
            this SecretStoreBuilder builder,
            IConfiguration configuration)
        {
            var provider = new ConfigurationSecretProvider(configuration);
            return builder.AddProvider(provider);
        }
    }
}