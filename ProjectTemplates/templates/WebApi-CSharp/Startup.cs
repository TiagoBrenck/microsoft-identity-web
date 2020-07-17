using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
#if (RequiresHttps)
using Microsoft.AspNetCore.HttpsPolicy;
#endif
using Microsoft.AspNetCore.Mvc;
#if (OrganizationalAuth || IndividualB2CAuth)
using Microsoft.AspNetCore.Authentication;
#endif
#if (OrganizationalAuth)
using Microsoft.Identity.Web;
using Microsoft.Identity.Web.TokenCacheProviders.InMemory;
#endif
#if (IndividualB2CAuth)
using Microsoft.Identity.Web;
using Microsoft.Identity.Web.TokenCacheProviders.InMemory;
#endif
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Authentication.JwtBearer;
#if (GenerateApiOrGraph)
using Company.WebApplication1.Services;
#endif
#if (CallsMicrosoftGraph)
using Microsoft.Graph;
#endif
namespace Company.WebApplication1
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
#if (OrganizationalAuth)
            // Adds Microsoft Identity platform (AAD v2.0) support to protect this Api
            services.AddMicrosoftWebApiAuthentication(Configuration, "AzureAd")
#if (GenerateApi || CallsMicrosoftGraph)
                    .AddMicrosoftWebAppCallsWebApi(Configuration, 
                                                   "AzureAd")
                    .AddInMemoryTokenCaches();

#else
                    ;
#endif
#if (GenerateApi)
            services.AddDownstreamWebApiService(Configuration);
#endif
#if (CallsMicrosoftGraph)
            services.AddMicrosoftGraph(Configuration.GetValue<string>("CalledApi:CalledApiScopes")?.Split(' '),
                                       Configuration.GetValue<string>("CalledApi:CalledApiUrl"));
#endif
#elif (IndividualB2CAuth)
            services.AddMicrosoftWebApiAuthentication(Configuration, "AzureAdB2C")
#if (GenerateApi)
                    .AddMicrosoftWebAppCallsWebApi(Configuration, 
                                                   "AzureAdB2C")
                    .AddInMemoryTokenCaches();

            services.AddDownstreamWebApiService(Configuration);
#else
                    ;
#endif
#endif

            services.AddControllers();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
#if (RequiresHttps)

            app.UseHttpsRedirection();
#endif

            app.UseRouting();

#if (OrganizationalAuth || IndividualAuth)
            app.UseAuthentication();
#endif
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}
