using Autofac;
using Autofac.Extensions.DependencyInjection;
using Contracts.Commands;
using Contracts.Models;
using IdentityServer.Configuration;
using IdentityServer.CultureResources;
using IdentityServer.Extensions;
using IdentityServer.Models;
using IdentityServer.Services;
using IdentityServer4.MongoDB.Interfaces;
using IdentityServer4.MongoDB.Mappers;
using IdentityServer4.Services;
using MassTransit;
using MassTransit.Util;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Localization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Serilog;
using Serilog.Exceptions;
using Serilog.Sinks.Elasticsearch;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;

namespace IdentityServer
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
            Log.Logger = new LoggerConfiguration()
                .Enrich.FromLogContext()
                .Enrich.WithExceptionDetails()
                .WriteTo.Console()
                .WriteTo.Elasticsearch(new ElasticsearchSinkOptions(new Uri($"http://{Environment.GetEnvironmentVariable("ES_HOST")}:{Environment.GetEnvironmentVariable("ES_PORT")}/"))
                {
                    AutoRegisterTemplate = true,
                    AutoRegisterTemplateVersion = AutoRegisterTemplateVersion.ESv6,
                    IndexFormat = "logstash-identityserver-{0:yyyy}"
                })
            .CreateLogger();
        }

        public IContainer ApplicationContainer { get; private set; }
        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public IServiceProvider ConfigureServices(IServiceCollection services)
        {
            services.AddCors(options =>
            {
                // this defines a CORS policy called "default"
                options.AddPolicy("default", policy =>
                {
                    policy.AllowAnyOrigin()
                        .AllowAnyHeader()
                        .AllowAnyMethod();
                });
            });

            services.AddDataProtection()
                .SetApplicationName("identity-server")
                .PersistKeysToFileSystem(new DirectoryInfo(@"/var/dpkeys/"));

            services.Configure<MongoDBSettings>(options =>
            {
                options.ConnectionString
                    = $"mongodb://{Environment.GetEnvironmentVariable("MONGODB_USERNAME")}:{Environment.GetEnvironmentVariable("MONGODB_PASSWORD")}@{Environment.GetEnvironmentVariable("COMPANY_MONGODB_HOST")}:{Environment.GetEnvironmentVariable("COMPANY_MONGODB_PORT")}";
                options.Database
                    = $"{Environment.GetEnvironmentVariable("COMPANY_MONGODB_DATABASE_NAME")}";
            });

            services.AddIdentityWithMongoStoresUsingCustomTypes<ApplicationUser, ApplicationUserRole>($"mongodb://{Environment.GetEnvironmentVariable("MONGODB_USERNAME")}:{Environment.GetEnvironmentVariable("MONGODB_PASSWORD")}@{Environment.GetEnvironmentVariable("USER_MONGODB_HOST")}:{Environment.GetEnvironmentVariable("USER_MONGODB_PORT")}/{Environment.GetEnvironmentVariable("USER_MONGODB_DATABASE_NAME")}")
                .AddDefaultTokenProviders();

            services.Configure<IdentityOptions>(options =>
            {
                // Password settings
                options.Password.RequireDigit = false;
                options.Password.RequiredLength = 6;
                options.Password.RequireNonAlphanumeric = false;
                options.Password.RequireUppercase = false;
                options.Password.RequireLowercase = false;
                options.Password.RequiredUniqueChars = 5;

                options.User.RequireUniqueEmail = true;
                //options.SignIn.RequireConfirmedEmail = true;

                options.Tokens.EmailConfirmationTokenProvider = "Phone";
            });
            services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
            services.AddSingleton<LocService>();
            services.AddLocalization(options => options.ResourcesPath = "Resources");

            services.AddMvc()
             .AddViewLocalization()
             .AddDataAnnotationsLocalization(options =>
             {
                 options.DataAnnotationLocalizerProvider = (type, factory) =>
                 {
                     var assemblyName = new AssemblyName(typeof(SharedResource).GetTypeInfo().Assembly.FullName);
                     return factory.Create("SharedResource", assemblyName.Name);
                 };
             });

            services.Configure<RequestLocalizationOptions>(
                options =>
                {
                    var supportedCultures = new List<CultureInfo>
                        {
                            new CultureInfo("vi-VN"),
                            new CultureInfo("en-US")
                        };

                    options.DefaultRequestCulture = new RequestCulture("vi-VN");
                    options.SupportedCultures = supportedCultures;
                    options.SupportedUICultures = supportedCultures;

                    var providerQuery = new LocalizationQueryProvider
                    {
                        QueryParameterName = "ui_locales"
                    };

                    // Cookie is required for the logout, query parameters at not supported with the endsession endpoint
                    // Only works in the same domain
                    var providerCookie = new LocalizationCookieProvider
                    {
                        CookieName = "defaultLocale"
                    };
                    //options.RequestCultureProviders.Insert(0, providerCookie);
                    options.RequestCultureProviders.Insert(0, providerQuery);
                });

            services.AddTransient<IProfileService, IdentityWithAdditionalClaimsProfileService>();
            services.Configure<IISOptions>(iis =>
            {
                iis.AuthenticationDisplayName = "Windows";
                iis.AutomaticAuthentication = false;
            });

            var dict = new Dictionary<string, string>
            {
                {"ConnectionString", $"mongodb://{Environment.GetEnvironmentVariable("MONGODB_USERNAME")}:{Environment.GetEnvironmentVariable("MONGODB_PASSWORD")}@{Environment.GetEnvironmentVariable("IDENTITYSERVER_MONGODB_HOST")}:{Environment.GetEnvironmentVariable("IDENTITYSERVER_MONGODB_PORT")}"},
                {"Database", $"{Environment.GetEnvironmentVariable("IDENTITYSERVER_MONGODB_DATABASE_NAME")}"}
            };
            var cfgbuilder = new ConfigurationBuilder();
            cfgbuilder.AddInMemoryCollection(dict);
            var identityServerConfig = cfgbuilder.Build();

            services.AddIdentityServer()
                .AddConfigurationStore(identityServerConfig)
                .AddOperationalStore(identityServerConfig)
                .AddDeveloperSigningCredential()
                .AddExtensionGrantValidator<Extensions.ExtensionGrantValidator>()
                .AddExtensionGrantValidator<Extensions.NoSubjectExtensionGrantValidator>()
                .AddJwtBearerClientAuthentication()
                .AddAppAuthRedirectUriValidator()
                .AddAspNetIdentity<ApplicationUser>().AddProfileService<IdentityWithAdditionalClaimsProfileService>();

            services.AddExternalIdentityProviders();

            var builder = new ContainerBuilder();
            var timeout = TimeSpan.FromSeconds(10);

            builder.Register(c => new MessageRequestClient<ICreateCompany, Company>(c.Resolve<IBus>(), new Uri($"rabbitmq://{Environment.GetEnvironmentVariable("RABBITMQ_HOST")}/create_company"), timeout))
               .As<IRequestClient<ICreateCompany, Company>>()
               .SingleInstance();
            builder.Register(c => new MessageRequestClient<IUploadLogoCompany, Company>(c.Resolve<IBus>(), new Uri($"rabbitmq://{Environment.GetEnvironmentVariable("RABBITMQ_HOST")}/upload_logo_company"), timeout))
               .As<IRequestClient<IUploadLogoCompany, Company>>()
               .SingleInstance();
            builder.Register(c => new MessageRequestClient<ICountSendActiveAccount, ISendActiveAccountCounted>(c.Resolve<IBus>(), new Uri($"rabbitmq://{Environment.GetEnvironmentVariable("RABBITMQ_HOST")}/count_send_active_account"), timeout))
              .As<IRequestClient<ICountSendActiveAccount, ISendActiveAccountCounted>>()
              .SingleInstance();

            builder.Register(c =>
            {
                return Bus.Factory.CreateUsingRabbitMq(sbc =>
                    sbc.Host(new Uri($"rabbitmq://{Environment.GetEnvironmentVariable("RABBITMQ_HOST")}/"), h =>
                    {
                        h.Username(Environment.GetEnvironmentVariable("RABBITMQ_USERNAME"));
                        h.Password(Environment.GetEnvironmentVariable("RABBITMQ_PASSWORD"));
                    })
                );
            })
            .As<IBus>()
            .As<IBusControl>()
            .As<IPublishEndpoint>()
            .SingleInstance();
            builder.Populate(services);

            builder.RegisterType<EmailSender>().As<IEmailSender>()
                .WithParameter("sendGridUser", "apikey")
                .WithParameter("sendGridKey", "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");

            builder.RegisterType<SMSSender>().As<ISMSSender>();

            ApplicationContainer = builder.Build();
            return new AutofacServiceProvider(ApplicationContainer);
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory, IApplicationLifetime applicationLifetime)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseBrowserLink();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
            }
            app.UseCors("default");
            loggerFactory.AddSerilog();

            IPHostEntry local = Dns.GetHostEntry(Environment.GetEnvironmentVariable("LOADBALANCER"));

            app.UseForwardedHeaders(new ForwardedHeadersOptions
            {
                ForwardedHeaders = ForwardedHeaders.All,
                RequireHeaderSymmetry = false,
                ForwardLimit = null,
                KnownProxies = { local.AddressList[0] }
            });
            app.UseMiddleware<SerilogMiddleware>();

            // Setup Databases
            using (var serviceScope = app.ApplicationServices.GetRequiredService<IServiceScopeFactory>().CreateScope())
            {
                EnsureSeedData(serviceScope.ServiceProvider.GetService<IConfigurationDbContext>());
            }

            app.UseIdentityServer();
            app.UseIdentityServerMongoDBTokenCleanup(applicationLifetime);

            var locOptions = app.ApplicationServices.GetService<IOptions<RequestLocalizationOptions>>();
            app.UseRequestLocalization(locOptions.Value);

            app.UseStaticFiles();
            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });

            //resolve the bus from the container
            var bus = ApplicationContainer.Resolve<IBusControl>();
            //start the bus
            var busHandle = TaskUtil.Await(() => bus.StartAsync());

            applicationLifetime.ApplicationStopped.Register(() => { busHandle.Stop(); ApplicationContainer.Dispose(); });
        }

        private static void EnsureSeedData(IConfigurationDbContext context)
        {
            if (!context.Clients.Any())
            {
                foreach (var client in Clients.Get().ToList())
                {
                    context.AddClient(client.ToEntity());
                }
            }

            if (!context.IdentityResources.Any())
            {
                foreach (var resource in Resources.GetIdentityResources().ToList())
                {
                    context.AddIdentityResource(resource.ToEntity());
                }
            }

            if (!context.ApiResources.Any())
            {
                foreach (var resource in Resources.GetApiResources().ToList())
                {
                    context.AddApiResource(resource.ToEntity());
                }
            }
        }
    }

    public static class ServiceExtensions
    {
        public static IServiceCollection AddExternalIdentityProviders(this IServiceCollection services)
        {
            services.AddAuthentication()
                .AddGoogle("Google", options =>
                {
                    options.ClientId = "1075839070656-ttuk3et51oavs0oupgou2bp651iu3s2q.apps.googleusercontent.com";
                    options.ClientSecret = "56G11UrHTPqqNYRH4HR_tLww";
                })
                .AddFacebook("Facebook", options =>
                {
                    options.AppId = "1905448366436405";
                    options.AppSecret = "88ad2f337bfc3a8644b9ac4667921ff7";
                });

            return services;
        }
    }
}
