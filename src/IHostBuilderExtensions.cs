using Arcus.Security.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using Arcus.Security.Providers.AzureKeyVault;
using Arcus.Security.Providers.AzureKeyVault.Authentication;
using Arcus.Security.Providers.AzureKeyVault.Configuration;
using GuardNet;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Secret = Arcus.Security.Core.Secret;

// ReSharper disable once CheckNamespace
namespace Microsoft.Extensions.Hosting
{
    public static class IHostBuilderExtensions
    {
        public static IHostBuilder ConfigureSecretStore(this IHostBuilder hostBuilder, Action<IConfiguration, SecretStoreBuilder> configureSecretStores)
        {
            return ConfigureSecretStore(hostBuilder, (context, config, secretStores) => configureSecretStores(config, secretStores));
        }

        public static IHostBuilder ConfigureSecretStore(this IHostBuilder hostBuilder, Action<HostBuilderContext, IConfiguration, SecretStoreBuilder> configureSecretStores)
        {
            return hostBuilder.ConfigureServices((context, services) =>
            {
                var builder = new SecretStoreBuilder(services);
                configureSecretStores(context, context.Configuration, builder);

                services.TryAddSingleton<ISecretProvider, CompositeSecretProvider>();
            });
        }
    }

    public class SecretStoreSource
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="SecretStoreSource"/> class.
        /// </summary>
        public SecretStoreSource(ISecretProvider secretProvider)
        {
            SecretProvider = secretProvider;
        }

        public ISecretProvider SecretProvider { get; }
    }

    public class SecretStoreBuilder
    {
        public SecretStoreBuilder(IServiceCollection services)
        {
            Services = services;
        }

        public IServiceCollection Services { get; }

        public SecretStoreBuilder AddProvider(ISecretProvider secretProvider)
        {
            Services.AddSingleton(new SecretStoreSource(secretProvider));
            return this;
        }
    }

    public static class SecretStoreBuilderExtensions
    {
        public static SecretStoreBuilder AddAzureKeyVault(this SecretStoreBuilder builder, IKeyVaultAuthentication authentication, IKeyVaultConfiguration configuration)
        {
            return builder.AddProvider(new KeyVaultSecretProvider(authentication, configuration));
        }
    }

    public class CompositeSecretProvider : ISecretProvider
    {
        private readonly ILogger<CompositeSecretProvider> _logger;

        /// <summary>
        /// Initializes a new instance of the <see cref="CompositeSecretProvider"/> class.
        /// </summary>
        public CompositeSecretProvider(IEnumerable<SecretStoreSource> secretProviderSources, ILogger<CompositeSecretProvider> logger)
        {
            Guard.NotNull(secretProviderSources, nameof(secretProviderSources));
            Guard.For<ArgumentException>(() => secretProviderSources.Any(source => source?.SecretProvider is null), "None of the registered secret providers should be 'null'");

            _logger = logger ?? NullLogger<CompositeSecretProvider>.Instance;
            SecretProviders = secretProviderSources.Select(source => source.SecretProvider);
        }

        internal IEnumerable<ISecretProvider> SecretProviders { get; }

        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns the secret key.</returns>
        /// <exception cref="System.ArgumentException">The <paramref name="secretName"/> must not be empty</exception>
        /// <exception cref="System.ArgumentNullException">The <paramref name="secretName"/> must not be null</exception>
        /// <exception cref="SecretNotFoundException">The secret was not found, using the given name</exception>
        public async Task<string> GetRawSecretAsync(string secretName)
        {
            Guard.NotNullOrEmpty(secretName, nameof(secretName));

            Secret secret = await GetSecretAsync(secretName);
            return secret?.Value;
        }

        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns a <see cref="Secret"/> that contains the secret key</returns>
        /// <exception cref="System.ArgumentException">The <paramref name="secretName"/> must not be empty</exception>
        /// <exception cref="System.ArgumentNullException">The <paramref name="secretName"/> must not be null</exception>
        /// <exception cref="SecretNotFoundException">The secret was not found, using the given name</exception>
        public async Task<Secret> GetSecretAsync(string secretName)
        {
            Guard.NotNullOrEmpty(secretName, nameof(secretName));

            if (!SecretProviders.Any())
            {
                var keyNotFoundException = new KeyNotFoundException("No secret providers are configured to retrieve the secret from");
                throw new SecretNotFoundException(secretName, keyNotFoundException);
            }

            Secret secret = await GetSecretFromProvidersAsync(secretName);
            return secret;
        }

        private async Task<Secret> GetSecretFromProvidersAsync(string secretName)
        {
            foreach (ISecretProvider secretProvider in SecretProviders)
            {
                try
                {
                    Secret secret = await secretProvider.GetSecretAsync(secretName);
                    if (!(secret?.Value is null))
                    {
                        return secret;
                    }
                }
                catch (Exception exception)
                {
                    _logger.LogTrace(exception, "Secret provider {Type} doesn't contain secret with name {SecretName}", secretProvider.GetType().Name, secretName);
                }
            }

            var keyNotFoundException = new KeyNotFoundException("None of the configured secret providers contains the requested secret");
            throw new SecretNotFoundException(secretName, keyNotFoundException);
        }
    }

    public class InMemorySecretProvider : ISecretProvider
    {
        private readonly IDictionary<string, Secret> _secrets;

        /// <summary>
        /// Initializes a new instance of the <see cref="InMemorySecretProvider"/> class.
        /// </summary>
        public InMemorySecretProvider(IDictionary<string, Secret> secrets)
        {
            Guard.NotNull(secrets, nameof(secrets));
            _secrets = secrets;
        }

        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns the secret key.</returns>
        /// <exception cref="System.ArgumentException">The <paramref name="secretName"/> must not be empty</exception>
        /// <exception cref="System.ArgumentNullException">The <paramref name="secretName"/> must not be null</exception>
        /// <exception cref="SecretNotFoundException">The secret was not found, using the given name</exception>
        public async Task<string> GetRawSecretAsync(string secretName)
        {
            Secret secret = await GetSecretAsync(secretName);
            return secret?.Value;
        }

        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns a <see cref="Secret"/> that contains the secret key</returns>
        /// <exception cref="System.ArgumentException">The <paramref name="secretName"/> must not be empty</exception>
        /// <exception cref="System.ArgumentNullException">The <paramref name="secretName"/> must not be null</exception>
        /// <exception cref="SecretNotFoundException">The secret was not found, using the given name</exception>
        public Task<Secret> GetSecretAsync(string secretName)
        {
            return Task.FromResult(_secrets[secretName]);
        }
    }
}
