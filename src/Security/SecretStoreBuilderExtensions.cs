using System.Collections;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using Arcus.Security.Core;
using Arcus.Security.Providers.AzureKeyVault;
using Arcus.Security.Providers.AzureKeyVault.Authentication;
using Arcus.Security.Providers.AzureKeyVault.Configuration;
using Microsoft.Extensions.Hosting;

namespace Arcus.Security.Startup.Security
{
    public static class SecretStoreBuilderExtensions
    {
        public static SecretStoreBuilder AddAzureKeyVaultProvider(
            this SecretStoreBuilder builder,
            IKeyVaultAuthentication authentication,
            IKeyVaultConfiguration configuration)
        {
            return builder.AddProvider(new KeyVaultSecretProvider(authentication, configuration));
        }

        public static SecretStoreBuilder AddAzureKeyVaultProviderWithCertificate(
            this SecretStoreBuilder builder,
            string clientId,
            X509Certificate2 certificate,
            string rawVaultUri)
        {
            return AddAzureKeyVaultProvider(
                builder,
                new CertificateBasedAuthentication(clientId, certificate),
                new KeyVaultConfiguration(rawVaultUri));
        }

        public static SecretStoreBuilder AddAzureKeyVaultProviderWithManagedServiceIdentity(
            this SecretStoreBuilder builder,
            string rawVaultUri,
            string connectionString = null,
            string azureADInstance = null)
        {
            return AddAzureKeyVaultProvider(
                builder,
                new ManagedServiceIdentityAuthentication(connectionString, azureADInstance),
                new KeyVaultConfiguration(rawVaultUri));
        }

        public static SecretStoreBuilder AddAzureKeyVaultProviderWithServicePrincipal(
            this SecretStoreBuilder builder,
            string clientId,
            string clientKey,
            string rawVaultUri)
        {
            return AddAzureKeyVaultProvider(
                builder,
                new ServicePrincipalAuthentication(clientId, clientKey),
                new KeyVaultConfiguration(rawVaultUri));
        }

        public static SecretStoreBuilder AddEnvironmentVariableProvider(this SecretStoreBuilder builder)
        {
            return builder.AddProvider(new EnvironmentVariableSecretProvider());
        }

        public static SecretStoreBuilder AddInMemoryProvider(
            this SecretStoreBuilder builder,
            IDictionary<string, Secret> secrets)
        {
            var provider = new InMemorySecretProvider(secrets);
            return builder.AddProvider(provider);
        }
    }
}