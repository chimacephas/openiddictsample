using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using OpenIddictSample.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;


namespace OpenIddictSample.Controllers
{
    [Route("api/auth")]
    [ApiController]
    public class AuthController : ControllerBase
    {

        private readonly IOptions<IdentityOptions> _identityOptions;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly UserManager<IdentityUser> _userManager;

        public AuthController(IOptions<IdentityOptions> identityOptions,
                                        SignInManager<IdentityUser> signInManager,
                                        UserManager<IdentityUser> userManager)
        {
            _identityOptions = identityOptions;
            _signInManager = signInManager;
            _userManager = userManager;
        }

        [HttpPost("authentication/token")]
        [AllowAnonymous]
        public async Task<IActionResult> Token()
        {

            try
            {
                var model = HttpContext.GetOpenIddictServerRequest();

                if (model.IsPasswordGrantType())
                {
                    var applicationUser = await _userManager.FindByNameAsync(model.Username);

                    if (applicationUser is null)
                    {
                        return BadRequest(new 
                        {
                            Error = OpenIddictConstants.Errors.InvalidGrant,
                            ErrorDescription = "Login or password is incorrect."
                        });
                    }

                    if (!await _signInManager.CanSignInAsync(applicationUser))
                    {
                        return BadRequest(new 
                        {
                            Error = OpenIddictConstants.Errors.AccessDenied,
                            ErrorDescription = "You are not allowed to sign in."
                        });
                    }

                    if (_userManager.SupportsUserTwoFactor && await _userManager.GetTwoFactorEnabledAsync(applicationUser))
                    {
                        return BadRequest(new 
                        {
                            Error = OpenIddictConstants.Errors.AccessDenied,
                            ErrorDescription = "You are not allowed to sign in."
                        });
                    }

                    if (_userManager.SupportsUserLockout && await _userManager.IsLockedOutAsync(applicationUser))
                    {
                        return BadRequest(new 
                        {
                            Error = OpenIddictConstants.Errors.AccessDenied,
                            ErrorDescription = "Your profile is temporary locked."
                        });
                    }

                    if (!await _userManager.CheckPasswordAsync(applicationUser, model.Password))
                    {
                        if (_userManager.SupportsUserLockout)
                        {
                            await _userManager.AccessFailedAsync(applicationUser);
                        }

                        return BadRequest(new 
                        {
                            Error = OpenIddictConstants.Errors.InvalidGrant,
                            ErrorDescription = "Login or password is incorrect."
                        });
                    }

                    if (_userManager.SupportsUserLockout)
                    {
                        await _userManager.ResetAccessFailedCountAsync(applicationUser);
                    }

                    await _userManager.UpdateAsync(applicationUser);

                    var ticket = await CreateTicketAsync(model, applicationUser);
                    return SignIn(ticket.Principal, ticket.Properties, ticket.AuthenticationScheme);
                }
                else if (model.IsRefreshTokenGrantType())
                {
                    var info = await HttpContext.AuthenticateAsync(
                        OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

                    var user = await _userManager.GetUserAsync(info.Principal);
                    if (user == null)
                    {
                        return BadRequest(new 
                        {
                            Error = OpenIddictConstants.Errors.InvalidGrant,
                            ErrorDescription = "The refresh token is no longer valid."
                        });
                    }

                    if (!await _signInManager.CanSignInAsync(user))
                    {
                        return BadRequest(new 
                        {
                            Error = OpenIddictConstants.Errors.InvalidGrant,
                            ErrorDescription = "The user is no longer allowed to sign in."
                        });
                    }

                    var ticket = await CreateTicketAsync(model, user, info.Properties);
                    return SignIn(ticket.Principal, ticket.Properties, ticket.AuthenticationScheme);
                }

                return BadRequest(new
                {
                    Error = OpenIddictConstants.Errors.UnsupportedGrantType,
                    ErrorDescription = "The specified grant type is not supported."
                });
            }
            catch (Exception ex)
            {
                return BadRequest(ex);
            }
        }

        private async Task<AuthenticationTicket> CreateTicketAsync(OpenIddictRequest oidcRequest, IdentityUser user,
            AuthenticationProperties properties = null)
        {
            var principal = await _signInManager.CreateUserPrincipalAsync(user);
            var identity = (ClaimsIdentity)principal.Identity;

            var ticket = new AuthenticationTicket(principal, properties, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

            if (!oidcRequest.IsRefreshTokenGrantType())
            {
                ticket.Principal.SetScopes(new[]
                {
                    OpenIddictConstants.Scopes.OpenId,
                    OpenIddictConstants.Scopes.Email,
                    OpenIddictConstants.Scopes.Profile,
                    OpenIddictConstants.Scopes.OfflineAccess,
                    OpenIddictConstants.Scopes.Roles,

                }.Intersect(oidcRequest.GetScopes()));
            }

            var destinations = new List<string>
            {
                OpenIddictConstants.Destinations.AccessToken
            };

            foreach (var claim in ticket.Principal.Claims)
            {
                if (claim.Type == _identityOptions.Value.ClaimsIdentity.SecurityStampClaimType)
                {
                    continue;
                }

                if ((claim.Type == OpenIddictConstants.Claims.Name && ticket.Principal.HasScope(OpenIddictConstants.Scopes.Profile)) ||
                    (claim.Type == OpenIddictConstants.Claims.Email && ticket.Principal.HasScope(OpenIddictConstants.Scopes.Email)) ||
                    (claim.Type == OpenIddictConstants.Claims.Role && ticket.Principal.HasScope(OpenIddictConstants.Claims.Role)) ||
                    (claim.Type == OpenIddictConstants.Claims.Audience && ticket.Principal.HasScope(OpenIddictConstants.Claims.Audience))

                    )
                {
                    destinations.Add(OpenIddictConstants.Destinations.IdentityToken);
                }

                claim.SetDestinations(destinations);
            }

            return ticket;
        }



        [HttpPost("authentication/signup")]
        [AllowAnonymous]
        public async Task<IActionResult> SignUp(UserSignUpDto dto)
        {

            var user = new IdentityUser
            {
                Email = dto.Email,
                UserName = dto.Email
            };

            var result = await _userManager.CreateAsync(user, dto.Password);

            if (result.Succeeded)
            {
                await _userManager.AddToRoleAsync(user, "User");

                return Ok();
            }

            return BadRequest(result.Errors.FirstOrDefault()?.Description);
        }
    }


}
