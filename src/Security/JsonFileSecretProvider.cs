using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Arcus.Security.Core;
using Microsoft.Extensions.Configuration;

namespace Arcus.Security.Startup.Security
{
    public class JsonFileSecretProvider : ISecretProvider
    {
        private readonly Lazy<IConfigurationRoot> _configuration;

        /// <summary>
        /// Initializes a new instance of the <see cref="JsonFileSecretProvider"/> class.
        /// </summary>
        public JsonFileSecretProvider(string jsonFile, bool optional, bool reloadOnChange)
        {
            _configuration = new Lazy<IConfigurationRoot>(
                () => new ConfigurationBuilder()
                      .AddJsonFile(jsonFile, optional, reloadOnChange)
                      .Build());
        }

        /// <summary>Retrieves the secret value, based on the given name</summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns a <see cref="T:Arcus.Security.Core.Secret" /> that contains the secret key</returns>
        /// <exception cref="T:System.ArgumentException">The <paramref name="secretName" /> must not be empty</exception>
        /// <exception cref="T:System.ArgumentNullException">The <paramref name="secretName" /> must not be null</exception>
        /// <exception cref="T:Arcus.Security.Core.SecretNotFoundException">The secret was not found, using the given name</exception>
        public async Task<Secret> GetSecretAsync(string secretName)
        {
            string secretValue = await GetRawSecretAsync(secretName);
            return new Secret(secretValue, "1.0.0");
        }

        /// <summary>Retrieves the secret value, based on the given name</summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns the secret key.</returns>
        /// <exception cref="T:System.ArgumentException">The <paramref name="secretName" /> must not be empty</exception>
        /// <exception cref="T:System.ArgumentNullException">The <paramref name="secretName" /> must not be null</exception>
        /// <exception cref="T:Arcus.Security.Core.SecretNotFoundException">The secret was not found, using the given name</exception>
        public Task<string> GetRawSecretAsync(string secretName)
        {
            var secretValue = _configuration.Value.GetValue<string>(secretName);
            return Task.FromResult(secretValue);
        }
    }
}
