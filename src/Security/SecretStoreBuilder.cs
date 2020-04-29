using Arcus.Security.Core;
using Arcus.Security.Startup.Security;
using Microsoft.Extensions.DependencyInjection;

namespace Microsoft.Extensions.Hosting {
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
}