/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using System.Collections.Generic;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Http;

namespace AspNet.Security.OAuth.EHealth
{
    /// <summary>
    /// Defines a set of options used by <see cref="EHealthAuthenticationHandler"/>.
    /// </summary>
    public class EHealthAuthenticationOptions : OAuthOptions
    {
        public string RedirectUri { get; set; }

        public EHealthAuthenticationOptions()
        {
            ClaimsIssuer = EHealthAuthenticationDefaults.Issuer;

            CallbackPath = new PathString(EHealthAuthenticationDefaults.CallbackPath);

            AuthorizationEndpoint = EHealthAuthenticationDefaults.AuthorizationEndpoint;
            TokenEndpoint = EHealthAuthenticationDefaults.TokenEndpoint;

            UserInformationEndpoint = EHealthAuthenticationDefaults.UserInformationEndpoint;


            /*
            ClaimActions.MapJsonKey(ClaimTypes.NameIdentifier, "uid");
            ClaimActions.MapJsonKey(ClaimTypes.GivenName, "first_name");
            ClaimActions.MapJsonKey(ClaimTypes.Surname, "last_name");
            ClaimActions.MapJsonKey(ClaimTypes.Hash, "hash");
            */
            ClaimActions.MapJsonKey("ehealth:expires_at", "expires_at");
            ClaimActions.MapJsonKey("ehealth:id", "id");
            ClaimActions.MapJsonKey("ehealth:user_id", "user_id");
            ClaimActions.MapJsonKey("ehealth:access_token", "value");
        }

        /// <summary>
        /// Gets the list of fields to retrieve from the user information endpoint.
        /// See https://vk.com/dev/fields for more information.
        /// </summary>
        public ISet<string> Scopes { get; } = new HashSet<string>
        {
            "employee:read",
            "employee:write",
            "employee_request:approve",
            "employee_request:read",
            "employee_request:write",
            "employee_request:reject",
            "legal_entity:read",
            "division:read",
            "division:write",
            "declaration_request:write",
            "declaration_request:read",
            "employee:deactivate",
            "otp:read otp:write",
        };
    }
}