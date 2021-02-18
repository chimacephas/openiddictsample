using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddictSample.Models;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace OpenIddictSample
{
    public partial class Startup
    {
        private async Task InitializeIdentityDbAsync(IServiceProvider services, CancellationToken cancellationToken = default)
        {
            using var scope = services.GetRequiredService<IServiceScopeFactory>().CreateScope();
            var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

            if (await manager.FindByClientIdAsync("SAP", cancellationToken) == null)
            {
                var descriptor = new OpenIddictApplicationDescriptor
                {
                    ClientId = "SAP",
                    ClientSecret = "178e196b-04b5-40ff-b235-7ac541eed1c9",
                    DisplayName = "SAP Api client",
                    Permissions =
                    {
                        OpenIddictConstants.Permissions.Endpoints.Token,
                        OpenIddictConstants.Permissions.GrantTypes.Password,
                        OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
                        OpenIddictConstants.Permissions.Scopes.Email,
                        OpenIddictConstants.Permissions.Scopes.Profile,
                        OpenIddictConstants.Permissions.Scopes.Roles,
                    }
                };

                await manager.CreateAsync(descriptor, cancellationToken);
            }
        }

        public void AddIdentityProvider(IServiceCollection services)
        {
            var authSettings = new OpenIddictServerConfig();

            Configuration.Bind(nameof(OpenIddictServerConfig), authSettings);
            var signingKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(authSettings.SecretKey));

            services.Configure<IdentityOptions>(options =>
            {
                options.ClaimsIdentity.UserNameClaimType = OpenIddictConstants.Claims.Name;
                options.ClaimsIdentity.UserIdClaimType = OpenIddictConstants.Claims.Subject;
                options.ClaimsIdentity.RoleClaimType = OpenIddictConstants.Claims.Role;

            });

            var x509Certificate = new X509Certificate2(Path.Combine(HostingEnvironment.WebRootPath, "auth.pfx")
                      , "1234567890", X509KeyStorageFlags.MachineKeySet);

            services.AddOpenIddict()
                .AddCore(options =>
                {
                    options.UseEntityFrameworkCore()
                        .UseDbContext<ApplicationDbContext>();
                })
                .AddServer(options =>
                {
                    options.RegisterScopes(OpenIddictConstants.Scopes.Email,
                        OpenIddictConstants.Scopes.Profile,
                        OpenIddictConstants.Scopes.Address,
                        OpenIddictConstants.Scopes.Phone,
                        OpenIddictConstants.Scopes.Roles,
                        OpenIddictConstants.Scopes.OfflineAccess,
                        OpenIddictConstants.Scopes.OpenId
                    );

                    options.SetTokenEndpointUris("/api/auth/authentication/token")
                        .AllowRefreshTokenFlow()
                        .AcceptAnonymousClients()
                        .AllowPasswordFlow()
                        .SetAccessTokenLifetime(TimeSpan.FromMinutes(60))
                        .SetIdentityTokenLifetime(TimeSpan.FromMinutes(60))
                        .SetRefreshTokenLifetime(TimeSpan.FromMinutes(120))

                        .AddEncryptionCertificate(x509Certificate)
                        .DisableAccessTokenEncryption()
                        .AddSigningCertificate(x509Certificate)
                        .IgnoreScopePermissions()
                        .UseAspNetCore()
                       .EnableTokenEndpointPassthrough();
                });

            JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();
            JwtSecurityTokenHandler.DefaultOutboundClaimTypeMap.Clear();

            services.AddAuthentication(x =>
            {
                x.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                x.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            }).AddJwtBearer(options =>
            {
                options.Authority = options.Authority = authSettings.Authority;
                options.RequireHttpsMetadata = authSettings.RequireHttps;
                options.SaveToken = true;
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    NameClaimType = OpenIddictConstants.Claims.Name,
                    RoleClaimType = OpenIddictConstants.Claims.Role,
                    IssuerSigningKey = signingKey,
                    ValidateAudience = false,
                    ValidateIssuer = false,
                };

                options.Events = new JwtBearerEvents
                {
                    OnAuthenticationFailed = context =>
                    {
                        if (context.Exception.GetType() == typeof(SecurityTokenExpiredException))
                        {
                            context.Response.Headers.Add("Token-Expired", "true");
                        }
                        return Task.CompletedTask;
                    }
                };
            });
        }
    }
}
