/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;

namespace AspNet.Security.OAuth.BankId
{
    /// <summary>
    /// Default values used by the BankID authentication middleware.
    /// </summary>
    public static class BankIdAuthenticationDefaults
    {
        /// <summary>
        /// Default value for <see cref="Microsoft.AspNetCore.Authentication.AuthenticationScheme.Name"/>.
        /// </summary>
        public const string AuthenticationScheme = "BankId";

        /// <summary>
        /// Default value for <see cref="Microsoft.AspNetCore.Authentication.AuthenticationScheme.DisplayName"/>.
        /// </summary>
        public const string DisplayName = "BankId";

        /// <summary>
        /// Default value for <see cref="AuthenticationSchemeOptions.ClaimsIssuer"/>.
        /// </summary>
        public const string Issuer = "BankId";

        /// <summary>
        /// Default value for <see cref="RemoteAuthenticationOptions.CallbackPath"/>.
        /// </summary>
        public const string CallbackPath = "/signin-bankid";

        /// <summary>
        /// Default value for <see cref="OAuthOptions.AuthorizationEndpoint"/>.
        /// </summary>
        public const string AuthorizationEndpoint = "https://bankid.org.ua/DataAccessService/das/authorize";
        public const string SandboxAuthorizationEndpoint = "https://bankid.privatbank.ua/DataAccessService/das/authorize";

        /// <summary>
        /// Default value for <see cref="OAuthOptions.TokenEndpoint"/>.
        /// </summary>
        public const string TokenEndpoint = "https://bankid.org.ua/DataAccessService/oauth/token";
        public const string SandboxTokenEndpoint = "https://bankid.privatbank.ua/DataAccessService/oauth/token";

        /// <summary>
        /// Default value for <see cref="OAuthOptions.UserInformationEndpoint"/>.
        /// For more info about this endpoint, see https://bankid.privatbank.ua/ResourceService/checked/data.
        /// </summary>
        public const string UserInformationEndpoint = "https://biprocessing.org.ua/ResourceService/checked/data";
        public const string SandboxUserInformationEndpoint = "https://bankid.privatbank.ua/ResourceService/checked/data";
    }
}
