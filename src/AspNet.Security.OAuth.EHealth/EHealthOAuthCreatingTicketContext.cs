using System;
using System.Globalization;
using System.Net.Http;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Http;
using Newtonsoft.Json.Linq;

namespace AspNet.Security.OAuth.EHealth
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="T:System.Security.Claims.ClaimsIdentity" />.
    /// </summary>
    public class EHealthOAuthCreatingTicketContext : ResultContext<OAuthOptions>
    {
        /// <summary>
        /// Initializes a new <see cref="T:Microsoft.AspNetCore.Authentication.OAuth.OAuthCreatingTicketContext" />.
        /// </summary>
        /// <param name="principal">The <see cref="T:System.Security.Claims.ClaimsPrincipal" />.</param>
        /// <param name="properties">The <see cref="T:Microsoft.AspNetCore.Authentication.AuthenticationProperties" />.</param>
        /// <param name="context">The HTTP environment.</param>
        /// <param name="scheme">The authentication scheme.</param>
        /// <param name="options">The options used by the authentication middleware.</param>
        /// <param name="backchannel">The HTTP client used by the authentication middleware</param>
        /// <param name="tokens">The tokens returned from the token endpoint.</param>
        public EHealthOAuthCreatingTicketContext(ClaimsPrincipal principal, AuthenticationProperties properties, HttpContext context, AuthenticationScheme scheme, OAuthOptions options, HttpClient backchannel, EHealthOAuthTokenResponse tokens)
            : this(principal, properties, context, scheme, options, backchannel, tokens, new JObject())
        {
        }

        /// <summary>
        /// Initializes a new <see cref="T:Microsoft.AspNetCore.Authentication.OAuth.OAuthCreatingTicketContext" />.
        /// </summary>
        /// <param name="principal">The <see cref="T:System.Security.Claims.ClaimsPrincipal" />.</param>
        /// <param name="properties">The <see cref="T:Microsoft.AspNetCore.Authentication.AuthenticationProperties" />.</param>
        /// <param name="context">The HTTP environment.</param>
        /// <param name="scheme">The authentication scheme.</param>
        /// <param name="options">The options used by the authentication middleware.</param>
        /// <param name="backchannel">The HTTP client used by the authentication middleware</param>
        /// <param name="tokens">The tokens returned from the token endpoint.</param>
        /// <param name="user">The JSON-serialized user.</param>
        public EHealthOAuthCreatingTicketContext(ClaimsPrincipal principal, AuthenticationProperties properties, HttpContext context, AuthenticationScheme scheme, OAuthOptions options, HttpClient backchannel, EHealthOAuthTokenResponse tokens, JObject user)
            : base(context, scheme, options)
        {
            TokenResponse = tokens ?? throw new ArgumentNullException(nameof(tokens));
            Backchannel = backchannel ?? throw new ArgumentNullException(nameof(backchannel));
            User = user ?? throw new ArgumentNullException(nameof(user));
            Principal = principal;
            Properties = properties;
        }

        /// <summary>
        /// Gets the JSON-serialized user or an empty
        /// <see cref="T:Newtonsoft.Json.Linq.JObject" /> if it is not available.
        /// </summary>
        public JObject User { get; }

        /// <summary>
        /// Gets the token response returned by the authentication service.
        /// </summary>
        public EHealthOAuthTokenResponse TokenResponse { get; }

        /// <summary>
        /// Gets the access token provided by the authentication service.
        /// </summary>
        public string AccessToken => TokenResponse.AccessToken;

        /// <summary>
        /// Gets the access token type provided by the authentication service.
        /// </summary>
        public string TokenType => TokenResponse.TokenType;

        /// <summary>
        /// Gets the refresh token provided by the authentication service.
        /// </summary>
        public string RefreshToken => TokenResponse.RefreshToken;

        /// <summary>Gets the access token expiration time.</summary>
        public TimeSpan? ExpiresIn => int.TryParse(TokenResponse.ExpiresIn, NumberStyles.Integer, CultureInfo.InvariantCulture, out var result) ? TimeSpan.FromSeconds(result) : new TimeSpan?();

        /// <summary>
        /// Gets the backchannel used to communicate with the provider.
        /// </summary>
        public HttpClient Backchannel { get; }

        /// <summary>
        /// Gets the main identity exposed by the authentication ticket.
        /// This property returns <c>null</c> when the ticket is <c>null</c>.
        /// </summary>
        public ClaimsIdentity Identity
        {
            get
            {
                var principal = Principal;
                return principal?.Identity as ClaimsIdentity;
            }
        }

        public void RunClaimActions()
        {
            RunClaimActions(User);
        }

        public void RunClaimActions(JObject userData)
        {
            if (userData == null)
                throw new ArgumentNullException(nameof(userData));
            foreach (var claimAction in Options.ClaimActions)
                claimAction.Run(userData, Identity, Options.ClaimsIssuer ?? Scheme.Name);
        }
    }
}