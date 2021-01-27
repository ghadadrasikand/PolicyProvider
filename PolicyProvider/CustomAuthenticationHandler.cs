﻿using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace AuthorizationPolicyProvider
{
    public class BasicAuthenticationOptions : AuthenticationSchemeOptions
    {
        
    }
    public class CustomAuthenticationHandler : AuthenticationHandler<BasicAuthenticationOptions>
    {
        private readonly ICustomAuthenticationManager customAuthenticationManager;
        public CustomAuthenticationHandler(
            IOptionsMonitor<BasicAuthenticationOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock,
            ICustomAuthenticationManager customAuthenticationManager) : base(options, logger, encoder, clock)
        {
            this.customAuthenticationManager = customAuthenticationManager;
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (!Request.Headers.ContainsKey("Authorization"))
                return AuthenticateResult.Fail("Unauthorized");
            string authorizationHeader = Request.Headers["Authorization"];
            if (string.IsNullOrEmpty(authorizationHeader))
                return AuthenticateResult.Fail("Unauthorized");
            if (!authorizationHeader.StartsWith("Bearer", StringComparison.CurrentCultureIgnoreCase))
                return AuthenticateResult.Fail("Unauthorized");
            string token = authorizationHeader.Substring("Bearer".Length).Trim();
            if (string.IsNullOrEmpty(token))
                return AuthenticateResult.Fail("Unauthorized");
            try
            {
                return ValidateToken(token);
            }
            catch (Exception ex)
            {
                return AuthenticateResult.Fail("Unauthorized");
            }
        }
        private AuthenticateResult ValidateToken(string token)
        {
            var validatedToken = customAuthenticationManager.Tokens.FirstOrDefault(t => t.Key == token);
            if (validatedToken.Key == null)
            {
                return AuthenticateResult.Fail("Unauthorized");
            }
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, validatedToken.Value),
                new Claim("DateOfJoining",validatedToken.Key)
            };
            var identity = new ClaimsIdentity(claims, Scheme.Name);
            var principal = new System.Security.Principal.GenericPrincipal(identity, null);
            var ticket = new AuthenticationTicket(principal, Scheme.Name);
            return AuthenticateResult.Success(ticket);
        }
    }
}
