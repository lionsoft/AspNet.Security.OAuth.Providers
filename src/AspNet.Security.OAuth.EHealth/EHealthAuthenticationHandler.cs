/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace AspNet.Security.OAuth.EHealth
{
    public class EHealthAuthenticationHandler : OAuthHandler<EHealthAuthenticationOptions>
    {
        public EHealthAuthenticationHandler(
            [NotNull] IOptionsMonitor<EHealthAuthenticationOptions> options,
            [NotNull] ILoggerFactory logger,
            [NotNull] UrlEncoder encoder,
            [NotNull] ISystemClock clock)
            : base(options, logger, encoder, clock)
        {
        }

        protected async Task<AuthenticationTicket> CreateTicketAsync([NotNull] ClaimsIdentity identity,
            [NotNull] AuthenticationProperties properties, [NotNull] EHealthOAuthTokenResponse tokens)
        {
/*
            var address = QueryHelpers.AddQueryString(Options.UserInformationEndpoint, "access_token", tokens.AccessToken);

            if (Options.Scopes.Count != 0)
            {
                address = QueryHelpers.AddQueryString(address, "scope", string.Join(" ", Options.Scopes));
            }

            var response = await Backchannel.GetAsync(address, Context.RequestAborted);
            if (!response.IsSuccessStatusCode)
            {
                Logger.LogError("An error occurred while retrieving the user profile: the remote server " +
                                "returned a {Status} response with the following payload: {Headers} {Body}.",
                                /* Status: #1# response.StatusCode,
                                /* Headers: #1# response.Headers.ToString(),
                                /* Body: #1# await response.Content.ReadAsStringAsync());

                throw new HttpRequestException("An error occurred while retrieving the user profile.");
            }

            var container = JObject.Parse(await response.Content.ReadAsStringAsync());
            var payload = container["response"].First as JObject;
*/

            var payload = tokens.Response.Response;
            var principal = new ClaimsPrincipal(identity);
            var context = new EHealthOAuthCreatingTicketContext(principal, properties, Context, Scheme, Options, Backchannel, tokens, payload);
            context.RunClaimActions(payload);

            //!!!await Options.Events.CreatingTicket(context);
            return await Task.FromResult(new AuthenticationTicket(context.Principal, context.Properties, Scheme.Name));
        }

        protected override string BuildChallengeUrl(AuthenticationProperties properties, string redirectUri)
        {
            return base.BuildChallengeUrl(properties, redirectUri);
        }

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            return base.HandleAuthenticateAsync();
        }

        private static async Task<string> Display(HttpResponseMessage response)
        {
            var output = new StringBuilder();
            output.Append("Status: " + response.StatusCode + ";");
            output.Append("Headers: " + response.Headers + ";");
            output.Append("Body: " + await response.Content.ReadAsStringAsync() + ";");
            return output.ToString();
        }

        protected new async Task<EHealthOAuthTokenResponse> ExchangeCodeAsync(string code, string redirectUri)
        {
            var oauthHandler = this;
            var content = JsonConvert.SerializeObject(new
            {
                token = new {
                    grant_type = "authorization_code",
                    code,
                    client_id = oauthHandler.Options.ClientId,
                    client_secret = oauthHandler.Options.ClientSecret,
                    redirect_uri = redirectUri,
                    scope = string.Join(" ", oauthHandler.Options.Scopes)
                }
            }, Formatting.None);
            var urlEncodedContent = new StringContent(content, Encoding.UTF8, "application/json");
            var response = await oauthHandler.Backchannel.SendAsync(
                new HttpRequestMessage(HttpMethod.Post, oauthHandler.Options.TokenEndpoint)
                {
                    Headers = { Accept = { new MediaTypeWithQualityHeaderValue("application/json") } },
                    Content = urlEncodedContent
                }, 
                oauthHandler.Context.RequestAborted);
            return response.IsSuccessStatusCode
                ? EHealthOAuthTokenResponse.Success(JObject.Parse(await response.Content.ReadAsStringAsync()))
                : EHealthOAuthTokenResponse.Failed(new Exception("OAuth token endpoint failure: " + await Display(response)));
        }

        protected override async Task<HandleRequestResult> HandleRemoteAuthenticateAsync()
        {
            var oauthHandler = this;
            var query = oauthHandler.Request.Query;
            var error = query["error"];
            if (!StringValues.IsNullOrEmpty(error))
            {
                var stringBuilder = new StringBuilder();
                stringBuilder.Append(error);
                var errorDescription = query["error_description"];
                if (!StringValues.IsNullOrEmpty(errorDescription))
                    stringBuilder.Append(";Description=").Append(errorDescription);
                var errorUri = query["error_uri"];
                if (!StringValues.IsNullOrEmpty(errorUri))
                    stringBuilder.Append(";Uri=").Append(errorUri);
                return HandleRequestResult.Fail(stringBuilder.ToString());
            }
            var code = query["code"];
            var state = query["state"];
            var properties = oauthHandler.Options.StateDataFormat.Unprotect(state) ?? new AuthenticationProperties();

            if (StringValues.IsNullOrEmpty(code))
                return HandleRequestResult.Fail("Code was not found.");
            var tokens = await oauthHandler.ExchangeCodeAsync(code, oauthHandler.BuildRedirectUri(oauthHandler.Options.CallbackPath));
            if (tokens.Error != null)
                return HandleRequestResult.Fail(tokens.Error);
            if (string.IsNullOrEmpty(tokens.AccessToken))
                return HandleRequestResult.Fail("Failed to retrieve access token.");
            var identity = new ClaimsIdentity(oauthHandler.ClaimsIssuer);
            if (oauthHandler.Options.SaveTokens)
            {
                var authenticationTokenList1 = new List<AuthenticationToken>();
                var authenticationTokenList2 = authenticationTokenList1;
                var authenticationToken1 = new AuthenticationToken {Name = "access_token"};
                var accessToken = tokens.AccessToken;
                authenticationToken1.Value = accessToken;
                authenticationTokenList2.Add(authenticationToken1);
                if (!string.IsNullOrEmpty(tokens.RefreshToken))
                {
                    var authenticationTokenList3 = authenticationTokenList1;
                    var authenticationToken2 = new AuthenticationToken {Name = "refresh_token"};
                    var refreshToken = tokens.RefreshToken;
                    authenticationToken2.Value = refreshToken;
                    authenticationTokenList3.Add(authenticationToken2);
                }
                if (!string.IsNullOrEmpty(tokens.TokenType))
                {
                    var authenticationTokenList3 = authenticationTokenList1;
                    var authenticationToken2 = new AuthenticationToken {Name = "token_type"};
                    var tokenType = tokens.TokenType;
                    authenticationToken2.Value = tokenType;
                    authenticationTokenList3.Add(authenticationToken2);
                }
                if (!string.IsNullOrEmpty(tokens.ExpiresIn) && int.TryParse(tokens.ExpiresIn, NumberStyles.Integer, CultureInfo.InvariantCulture, out var result))
                {
                    var dateTimeOffset = oauthHandler.Clock.UtcNow + TimeSpan.FromSeconds(result);
                    var authenticationTokenList3 = authenticationTokenList1;
                    var authenticationToken2 = new AuthenticationToken {Name = "expires_in"};
                    var str = dateTimeOffset.ToString("o", CultureInfo.InvariantCulture);
                    authenticationToken2.Value = str;
                    authenticationTokenList3.Add(authenticationToken2);
                }
                properties.StoreTokens(authenticationTokenList1);
            }
            var ticketAsync = await oauthHandler.CreateTicketAsync(identity, properties, tokens);
            return ticketAsync == null ? HandleRequestResult.Fail("Failed to retrieve user information from remote server.") : HandleRequestResult.Success(ticketAsync);
        }
    }
}