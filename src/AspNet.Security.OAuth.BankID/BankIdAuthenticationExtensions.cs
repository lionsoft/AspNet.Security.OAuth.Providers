/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;

namespace AspNet.Security.OAuth.BankId
{
    /// <summary>
    /// Extension methods to add BankID authentication capabilities to an HTTP application pipeline.
    /// </summary>
    public static class BankIdAuthenticationExtensions
    {
        /// <summary>
        /// Adds <see cref="BankIdAuthenticationHandler"/> to the specified
        /// <see cref="AuthenticationBuilder"/>, which enables BankID authentication capabilities.
        /// </summary>
        /// <param name="builder">The authentication builder.</param>
        /// <returns>The <see cref="AuthenticationBuilder"/>.</returns>
        public static AuthenticationBuilder AddBankId([NotNull] this AuthenticationBuilder builder)
        {
            return builder.AddBankId(BankIdAuthenticationDefaults.AuthenticationScheme, options => { });
        }

        /// <summary>
        /// Adds <see cref="BankIdAuthenticationHandler"/> to the specified
        /// <see cref="AuthenticationBuilder"/>, which enables BankID authentication capabilities.
        /// </summary>
        /// <param name="builder">The authentication builder.</param>
        /// <param name="configuration">The delegate used to configure the OpenID 2.0 options.</param>
        /// <returns>The <see cref="AuthenticationBuilder"/>.</returns>
        public static AuthenticationBuilder AddBankId(
            [NotNull] this AuthenticationBuilder builder,
            [NotNull] Action<BankIdAuthenticationOptions> configuration)
        {
            return builder.AddBankId(BankIdAuthenticationDefaults.AuthenticationScheme, configuration);
        }

        /// <summary>
        /// Adds <see cref="BankIdAuthenticationHandler"/> to the specified
        /// <see cref="AuthenticationBuilder"/>, which enables BankID authentication capabilities.
        /// </summary>
        /// <param name="builder">The authentication builder.</param>
        /// <param name="scheme">The authentication scheme associated with this instance.</param>
        /// <param name="configuration">The delegate used to configure the BankID options.</param>
        /// <returns>The <see cref="AuthenticationBuilder"/>.</returns>
        public static AuthenticationBuilder AddBankId(
            [NotNull] this AuthenticationBuilder builder, [NotNull] string scheme,
            [NotNull] Action<BankIdAuthenticationOptions> configuration)
        {
            return builder.AddBankId(scheme, BankIdAuthenticationDefaults.DisplayName, configuration);
        }

        /// <summary>
        /// Adds <see cref="BankIdAuthenticationHandler"/> to the specified
        /// <see cref="AuthenticationBuilder"/>, which enables BankID authentication capabilities.
        /// </summary>
        /// <param name="builder">The authentication builder.</param>
        /// <param name="scheme">The authentication scheme associated with this instance.</param>
        /// <param name="caption">The optional display name associated with this instance.</param>
        /// <param name="configuration">The delegate used to configure the BankID options.</param>
        /// <returns>The <see cref="AuthenticationBuilder"/>.</returns>
        public static AuthenticationBuilder AddBankId(
            [NotNull] this AuthenticationBuilder builder,
            [NotNull] string scheme, [CanBeNull] string caption,
            [NotNull] Action<BankIdAuthenticationOptions> configuration)
        {
            return builder.AddOAuth<BankIdAuthenticationOptions, BankIdAuthenticationHandler>(scheme, caption, configuration);
        }
    }
}
