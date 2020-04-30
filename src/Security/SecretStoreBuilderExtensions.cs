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
        public static SecretStoreBuilder AddAzureKeyVaultSecrets(
            this SecretStoreBuilder builder,
            IKeyVaultAuthentication authentication,
            IKeyVaultConfiguration configuration)
        {
            return builder.AddProvider(new KeyVaultSecretProvider(authentication, configuration));
        }

        public static SecretStoreBuilder AddAzureKeyVaultSecretsWithCertificate(
            this SecretStoreBuilder builder,
            string rawVaultUri,
            string clientId,
            X509Certificate2 certificate)
        {
            return AddAzureKeyVaultSecrets(
                builder,
                new CertificateBasedAuthentication(clientId, certificate),
                new KeyVaultConfiguration(rawVaultUri));
        }

        public static SecretStoreBuilder AddAzureKeyVaultSecretsWithManagedServiceIdentity(
            this SecretStoreBuilder builder,
            string rawVaultUri,
            string connectionString = null,
            string azureADInstance = null)
        {
            return AddAzureKeyVaultSecrets(
                builder,
                new ManagedServiceIdentityAuthentication(connectionString, azureADInstance),
                new KeyVaultConfiguration(rawVaultUri));
        }

        public static SecretStoreBuilder AddAzureKeyVaultSecretsWithServicePrincipal(
            this SecretStoreBuilder builder,
            string rawVaultUri,
            string clientId,
            string clientKey)
        {
            return AddAzureKeyVaultSecrets(
                builder,
                new ServicePrincipalAuthentication(clientId, clientKey),
                new KeyVaultConfiguration(rawVaultUri));
        }

        public static SecretStoreBuilder AddEnvironmentVariableSecrets(this SecretStoreBuilder builder)
        {
            return builder.AddProvider(new EnvironmentVariableSecretProvider());
        }

        public static SecretStoreBuilder AddInMemorySecrets(
            this SecretStoreBuilder builder,
            IDictionary<string, Secret> secrets)
        {
            var provider = new InMemorySecretProvider(secrets);
            return builder.AddProvider(provider);
        }

        public static SecretStoreBuilder AddJsonFileSecrets(
            this SecretStoreBuilder builder,
            string jsonFile,
            bool optional = false,
            bool reloadOnChange = false)
        {
            var provider = new JsonFileSecretProvider(jsonFile, optional, reloadOnChange);
            return builder.AddProvider(provider);
        }
    }
}