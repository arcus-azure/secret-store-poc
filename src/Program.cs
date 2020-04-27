using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Arcus.Security.Core;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

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
                .ConfigureSecretStore((context, config, builder) =>
                {
                    builder.AddProvider(new InMemorySecretProvider(new Dictionary<string, Secret>
                    {
                        ["MySecret"] = new Secret("123", "122asad-AD3-SDAF3223")
                    }));
                })
                .ConfigureSecretStore((context, config, builder) =>
                {
                    builder.AddProvider(new InMemorySecretProvider(new Dictionary<string, Secret>
                    {
                        ["OtherSecret"] = new Secret("1234", "lkj23-23 2-adsf-")
                    }));
                })
                .ConfigureWebHostDefaults(webBuilder =>
                {
                    webBuilder.UseStartup<Startup>();
                });
    }
}
