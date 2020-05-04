using System.Collections.Generic;
using Arcus.Security.Core;
using Arcus.Security.Providers.AzureKeyVault.Authentication;
using Arcus.Security.Providers.AzureKeyVault.Configuration;
using Arcus.Security.Startup.Security;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;

namespace Arcus.Security.Startup
{
    public class Program
    {
        public static void Main(string[] args)
        {
            CreateHostBuilder(args).Build().Run();
        }

        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
                .ConfigureHostConfiguration(configBuilder =>
                {
                    configBuilder.AddJsonFile("appsettings.Development.json")
                                 .AddJsonFile("appsettings.json");
                })
                .ConfigureSecretStore((context, config, builder) =>
                {
                    builder.AddConfiguration(config)
                           .AddEnvironmentVariables()
                           .AddAzureKeyVault(
                               new ServicePrincipalAuthentication("client-id", "client-key"),
                               new KeyVaultConfiguration("https://raw-vault-uri"))
                           .AddProvider(new InMemorySecretProvider(new Dictionary<string, Secret>
                           {
                               ["MySecret"] = new Secret("123", "122asad-AD3-SDAF3223")
                           }));
                })
                .ConfigureSecretStore((context, config, builder) =>
                {
                    builder.AddInMemory(new Dictionary<string, Secret>
                    {
                        ["OtherSecret"] = new Secret("1234", "lkj23-23 2-adsf-")
                    });
                })
                .ConfigureWebHostDefaults(webBuilder =>
                {
                    webBuilder.UseStartup<Startup>();
                });
    }
}
