// --------------------------------------------------------------------------------------------------------------------
// <copyright file="Startup.cs" company="GSD Logic">
//   Copyright © 2021 GSD Logic. All Rights Reserved.
// </copyright>
// --------------------------------------------------------------------------------------------------------------------

namespace ClientCertAuth
{
    using System.Linq;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Authentication.Certificate;
    using Microsoft.AspNetCore.Builder;
    using Microsoft.AspNetCore.Hosting;
    using Microsoft.AspNetCore.Http;
    using Microsoft.Extensions.DependencyInjection;
    using Microsoft.Extensions.Hosting;

    public class Startup
    {
        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseAuthentication();
            app.UseRouting();

            app.UseEndpoints(endpoints => { endpoints.MapGet("/", async context => { await context.Response.WriteAsync($"Hello {context.User?.Identity.Name}!"); }); });
        }

        // This method gets called by the runtime. Use this method to add services to the container.
        // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddAuthentication(CertificateAuthenticationDefaults.AuthenticationScheme)
                .AddCertificate(certificate =>
                {
                    certificate.Events = new CertificateAuthenticationEvents
                    {
                        OnCertificateValidated = context =>
                        {
                            var store = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
                            store.Open(OpenFlags.ReadOnly);

                            var certs = store.Certificates.Find(X509FindType.FindByThumbprint, "d73ca91102a2204a36459ed32213b467d7ce97fb", true);
                            store.Close();

                            if (certs.Count == 0)
                            {
                                context.Fail("Missing root certificate.");
                                return Task.CompletedTask;
                            }

                            var authority = certs[0];

                            var chain = new X509Chain();
                            chain.ChainPolicy.ExtraStore.Add(authority);

                            if (!chain.Build(context.ClientCertificate))
                            {
                                context.Fail("Trust chain did not complete to the known authority anchor.");
                                return Task.CompletedTask;
                            }

                            if (chain.ChainElements
                                .Cast<X509ChainElement>()
                                .All(x => x.Certificate.Thumbprint != authority.Thumbprint))
                            {
                                context.Fail("Trust chain did not complete to the known authority anchor.");
                                return Task.CompletedTask;
                            }

                            context.Success();
                            return Task.CompletedTask;
                        }
                    };
                });
        }
    }
}