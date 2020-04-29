using Arcus.Security.Core;

namespace Arcus.Security.Startup.Security
{
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
}