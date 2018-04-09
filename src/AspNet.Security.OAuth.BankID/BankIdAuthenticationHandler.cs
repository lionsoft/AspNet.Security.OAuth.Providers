/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
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
using Newtonsoft.Json.Linq;

namespace AspNet.Security.OAuth.BankId
{
    public class BankIdAuthenticationHandler : OAuthHandler<BankIdAuthenticationOptions>
    {
        public BankIdAuthenticationHandler(
            [NotNull] IOptionsMonitor<BankIdAuthenticationOptions> options,
            [NotNull] ILoggerFactory logger,
            [NotNull] UrlEncoder encoder,
            [NotNull] ISystemClock clock)
            : base(options, logger, encoder, clock)
        {
        }

        protected override string BuildChallengeUrl(AuthenticationProperties properties, string redirectUri)
        {
            return QueryHelpers.AddQueryString(Options.AuthorizationEndpoint, new Dictionary<string, string>
            {
                { "response_type", "code" },
                { "client_id", Options.ClientId },
                { "redirect_uri", redirectUri },
            });
        }

        /// <inheritdoc />
        protected override async Task<HandleRequestResult> HandleRemoteAuthenticateAsync()
        {
            var properties = new AuthenticationProperties();
            var query = Request.Query;
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

            if (StringValues.IsNullOrEmpty(code))
                return HandleRequestResult.Fail("Code was not found.");
            var tokens = await ExchangeCodeAsync(code, BuildRedirectUri(Options.CallbackPath));
            if (tokens.Error != null)
                return HandleRequestResult.Fail(tokens.Error);
            if (string.IsNullOrEmpty(tokens.AccessToken))
                return HandleRequestResult.Fail("Failed to retrieve access token.");
            var identity = new ClaimsIdentity(ClaimsIssuer);
            if (Options.SaveTokens)
            {
                var authenticationTokenList = new List<AuthenticationToken>
                {
                    new AuthenticationToken { Name = "access_token", Value = tokens.AccessToken }
                };
                if (!string.IsNullOrEmpty(tokens.RefreshToken))
                    authenticationTokenList.Add(new AuthenticationToken { Name = "refresh_token", Value = tokens.RefreshToken });
                if (!string.IsNullOrEmpty(tokens.TokenType))
                    authenticationTokenList.Add(new AuthenticationToken { Name = "token_type", Value = tokens.TokenType });
                if (!string.IsNullOrEmpty(tokens.ExpiresIn) && int.TryParse(tokens.ExpiresIn, NumberStyles.Integer, CultureInfo.InvariantCulture, out var result))
                {
                    var dateTimeOffset = Clock.UtcNow + TimeSpan.FromSeconds(result);
                    authenticationTokenList.Add(new AuthenticationToken
                    {
                        Name = "expires_at", Value = dateTimeOffset.ToString("o", CultureInfo.InvariantCulture)
                    });
                }
                properties.StoreTokens(authenticationTokenList);
            }
            var ticketAsync = await CreateTicketAsync(identity, properties, tokens);
            return ticketAsync == null 
                ? HandleRequestResult.Fail("Failed to retrieve user information from remote server.") 
                : HandleRequestResult.Success(ticketAsync);
        }

        private static async Task<string> Display(HttpResponseMessage response)
        {
            var output = new StringBuilder();
            output.Append("Status: " + response.StatusCode + ";");
            output.Append("Headers: " + response.Headers + ";");
            output.Append("Body: " + await response.Content.ReadAsStringAsync() + ";");
            return output.ToString();
        }

        private static string MakeBankIDClientSecret(string clientId, string clientSecret, string code)
        {
            var res = clientId + clientSecret + code;
            var hash = new SHA1Managed().ComputeHash(Encoding.UTF8.GetBytes(res));
            res = string.Join("", hash.Select(b => b.ToString("x2")).ToArray());
            return res;
        }

        protected override async Task<OAuthTokenResponse> ExchangeCodeAsync(string code, string redirectUri)
        {
            var address = QueryHelpers.AddQueryString(Options.TokenEndpoint, new Dictionary<string, string>
            {
                { "grant_type", "authorization_code" },
                { "client_id", Options.ClientId },
                { "client_secret", MakeBankIDClientSecret(Options.ClientId, Options.ClientSecret, code) },
                { nameof (code), code },
                { "redirect_uri", redirectUri },
            });
            var response = await Backchannel.SendAsync(new HttpRequestMessage(HttpMethod.Get, address)
                {
                    Headers = { Accept = { new MediaTypeWithQualityHeaderValue("application/json") } }
                }, 
                Context.RequestAborted);
            return response.IsSuccessStatusCode 
                ? OAuthTokenResponse.Success(JObject.Parse(await response.Content.ReadAsStringAsync())) 
                : OAuthTokenResponse.Failed(new Exception("OAuth token endpoint failure: " + await Display(response)));
        }

        public StringContent ToJsonContent(object body) => body == null ? null : new StringContent(JObject.FromObject(body).ToString(), Encoding.UTF8, "application/json");

        protected override async Task<AuthenticationTicket> CreateTicketAsync([NotNull] ClaimsIdentity identity,
            [NotNull] AuthenticationProperties properties, [NotNull] OAuthTokenResponse tokens)
        {
            var request = new HttpRequestMessage(HttpMethod.Post, Options.UserInformationEndpoint);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", $"{tokens.AccessToken},Id {Options.ClientId}");
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            request.Content = ToJsonContent(new
            {
                type = "physical",
                fields = new [] {"firstName", "middleName", "lastName", "phone", "inn", "clId", "clIdText", "birthDay","email","sex","resident","dateModification"}
            });

            var response = await Backchannel.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, Context.RequestAborted);
            if (!response.IsSuccessStatusCode)
            {
                Logger.LogError("An error occurred while retrieving the user profile: the remote server " +
                                "returned a {Status} response with the following payload: {Headers} {Body}.",
                                /* Status: */ response.StatusCode,
                                /* Headers: */ response.Headers.ToString(),
                                /* Body: */ await response.Content.ReadAsStringAsync());

                throw new HttpRequestException("An error occurred while retrieving the user profile.");
            }

            var payload = JObject.Parse(await response.Content.ReadAsStringAsync());

            var principal = new ClaimsPrincipal(identity);
            var context = new OAuthCreatingTicketContext(principal, properties, Context, Scheme, Options, Backchannel, tokens, payload);

            context.RunClaimActions(payload);

            await Options.Events.CreatingTicket(context);
            return new AuthenticationTicket(context.Principal, context.Properties, Scheme.Name);
        }
    }
}
