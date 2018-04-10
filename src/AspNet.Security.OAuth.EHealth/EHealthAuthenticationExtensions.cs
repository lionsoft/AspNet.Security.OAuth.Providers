/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using AspNet.Security.OAuth.EHealth;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// Extension methods to add EHealth authentication capabilities to an HTTP application pipeline.
    /// </summary>
    public static class EHealthAuthenticationExtensions
    {
        /// <summary>
        /// Adds <see cref="EHealthAuthenticationHandler"/> to the specified
        /// <see cref="AuthenticationBuilder"/>, which enables EHealth authentication capabilities.
        /// </summary>
        /// <param name="builder">The authentication builder.</param>
        /// <returns>The <see cref="AuthenticationBuilder"/>.</returns>
        public static AuthenticationBuilder AddEHealth([NotNull] this AuthenticationBuilder builder)
        {
            return builder.AddEHealth(EHealthAuthenticationDefaults.AuthenticationScheme, options => { });
        }

        /// <summary>
        /// Adds <see cref="EHealthAuthenticationHandler"/> to the specified
        /// <see cref="AuthenticationBuilder"/>, which enables EHealth authentication capabilities.
        /// </summary>
        /// <param name="builder">The authentication builder.</param>
        /// <param name="configuration">The delegate used to configure the EHealth options.</param>
        /// <returns>The <see cref="AuthenticationBuilder"/>.</returns>
        public static AuthenticationBuilder AddEHealth(
            [NotNull] this AuthenticationBuilder builder,
            [NotNull] Action<EHealthAuthenticationOptions> configuration)
        {
            return builder.AddEHealth(EHealthAuthenticationDefaults.AuthenticationScheme, configuration);
        }

        /// <summary>
        /// Adds <see cref="EHealthAuthenticationHandler"/> to the specified
        /// <see cref="AuthenticationBuilder"/>, which enables EHealth authentication capabilities.
        /// </summary>
        /// <param name="builder">The authentication builder.</param>
        /// <param name="scheme">The authentication scheme associated with this instance.</param>
        /// <param name="configuration">The delegate used to configure the EHealth options.</param>
        /// <returns>The <see cref="AuthenticationBuilder"/>.</returns>
        public static AuthenticationBuilder AddEHealth(
            [NotNull] this AuthenticationBuilder builder, [NotNull] string scheme, 
            [NotNull] Action<EHealthAuthenticationOptions> configuration)
        {
            return builder.AddEHealth(scheme, EHealthAuthenticationDefaults.DisplayName, configuration);
        }

        /// <summary>
        /// Adds <see cref="EHealthAuthenticationHandler"/> to the specified
        /// <see cref="AuthenticationBuilder"/>, which enables EHealth authentication capabilities.
        /// </summary>
        /// <param name="builder">The authentication builder.</param>
        /// <param name="scheme">The authentication scheme associated with this instance.</param>
        /// <param name="caption">The optional display name associated with this instance.</param>
        /// <param name="configuration">The delegate used to configure the EHealth options.</param>
        /// <returns>The <see cref="AuthenticationBuilder"/>.</returns>
        public static AuthenticationBuilder AddEHealth(
            [NotNull] this AuthenticationBuilder builder,
            [NotNull] string scheme, [CanBeNull] string caption,
            [NotNull] Action<EHealthAuthenticationOptions> configuration)
        {
            return builder.AddOAuth<EHealthAuthenticationOptions, EHealthAuthenticationHandler>(scheme, caption, configuration);
        }
    }
}