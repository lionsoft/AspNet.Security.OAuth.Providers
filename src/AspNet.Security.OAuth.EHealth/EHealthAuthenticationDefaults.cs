/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;

namespace AspNet.Security.OAuth.EHealth
{
    /// <summary>
    /// Default values used by the Vkontakte authentication middleware.
    /// </summary>
    public static class EHealthAuthenticationDefaults
    {
        /// <summary>
        /// Default value for <see cref="Microsoft.AspNetCore.Authentication.AuthenticationScheme.Name"/>.
        /// </summary>
        public const string AuthenticationScheme = "EHealth";

        /// <summary>
        /// Default value for <see cref="Microsoft.AspNetCore.Authentication.AuthenticationScheme.DisplayName"/>.
        /// </summary>
        public const string DisplayName = "EHealth";

        /// <summary>
        /// Default value for <see cref="AuthenticationSchemeOptions.ClaimsIssuer"/>.
        /// </summary>
        public const string Issuer = "EHealth";

        /// <summary>
        /// Default value for <see cref="RemoteAuthenticationOptions.CallbackPath"/>.
        /// </summary>
        public const string CallbackPath = "/signin-ehealth";

        /// <summary>
        /// Default value for <see cref="OAuthOptions.AuthorizationEndpoint"/>.
        /// </summary>
        public const string AuthorizationEndpoint = "http://auth.demo.ehealth.world/sign-in/";

        /// <summary>
        /// Default value for <see cref="OAuthOptions.TokenEndpoint"/>.
        /// </summary>
        public const string TokenEndpoint = "http://demo.ehealth.world/oauth/tokens/";

        /// <summary>
        /// Default value for <see cref="OAuthOptions.UserInformationEndpoint"/>.
        /// </summary>
        public const string UserInformationEndpoint = "http://demo.ehealth.world/user/";
    }
}