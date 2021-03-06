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

        public StringContent ToJsonContent(object body) => body == null ? null : new StringContent(JObject.FromObject(body).ToString(), Encoding.UTF8, "application/json");

        private static async Task<string> Display(HttpResponseMessage response)
        {
            var output = new StringBuilder();
            output.Append("Status: " + response.StatusCode + ";");
            output.Append("Headers: " + response.Headers + ";");
            output.Append("Body: " + await response.Content.ReadAsStringAsync() + ";");
            return output.ToString();
        }

        /// <inheritdoc />
        protected override async Task<HandleRequestResult> HandleRemoteAuthenticateAsync()
        {
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
            var state = query["state"];
            var properties = Options.StateDataFormat.Unprotect(state) ?? new AuthenticationProperties();

            if (StringValues.IsNullOrEmpty(code))
                return HandleRequestResult.Fail("Code was not found.");
            var tok = await ExchangeCodeAsync(code, BuildRedirectUri(Options.CallbackPath));
            var tokens = EHealthOAuthTokenResponse.Success(tok.Response);
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
                        Name = "expires_at",
                        Value = dateTimeOffset.ToString("o", CultureInfo.InvariantCulture)
                    });
                }
                properties.StoreTokens(authenticationTokenList);
            }
            var ticketAsync = await CreateTicketAsync(identity, properties, tokens.Response);
            return ticketAsync == null 
                ? HandleRequestResult.Fail("Failed to retrieve user information from remote server.") 
                : HandleRequestResult.Success(ticketAsync);
        }

        /// <inheritdoc />
        protected override async Task<OAuthTokenResponse> ExchangeCodeAsync(string code, string redirectUri)
        {
            var content = ToJsonContent(new
            {
                token = new
                {
                    grant_type = "authorization_code",
                    code,
                    client_id = Options.ClientId,
                    client_secret = Options.ClientSecret,
                    redirect_uri = redirectUri,
                    scope = string.Join(" ", Options.Scopes)
                }
            });

            var response = await Backchannel.SendAsync(new HttpRequestMessage(HttpMethod.Post, Options.TokenEndpoint)
                {
                    Headers = { Accept = { new MediaTypeWithQualityHeaderValue("application/json") } },
                    Content = content
                },
                Context.RequestAborted);
            return response.IsSuccessStatusCode
                ? OAuthTokenResponse.Success(JObject.Parse(await response.Content.ReadAsStringAsync()))
                : OAuthTokenResponse.Failed(new Exception("OAuth token endpoint failure: " + await Display(response)));
        }

        /*
                protected new async Task<EHealthOAuthTokenResponse> ExchangeCodeAsync(string code, string redirectUri)
                {
                    var content = JsonConvert.SerializeObject(new
                    {
                        token = new
                        {
                            grant_type = "authorization_code",
                            code,
                            client_id = Options.ClientId,
                            client_secret = Options.ClientSecret,
                            redirect_uri = redirectUri,
                            scope = string.Join(" ", Options.Scopes)
                        }
                    }, Formatting.None);
                    var urlEncodedContent = new StringContent(content, Encoding.UTF8, "application/json");
                    var response = await Backchannel.SendAsync(
                        new HttpRequestMessage(HttpMethod.Post, Options.TokenEndpoint)
                        {
                            Headers = { Accept = { new MediaTypeWithQualityHeaderValue("application/json") } },
                            Content = urlEncodedContent
                        },
                        Context.RequestAborted);
                    return response.IsSuccessStatusCode
                        ? EHealthOAuthTokenResponse.Success(JObject.Parse(await response.Content.ReadAsStringAsync()))
                        : EHealthOAuthTokenResponse.Failed(new Exception("OAuth token endpoint failure: " + await Display(response)));
                }
        */

        /*
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
                                                    /* Status: #2# response.StatusCode,
                                                    /* Headers: #2# response.Headers.ToString(),
                                                    /* Body: #2# await response.Content.ReadAsStringAsync());

                                    throw new HttpRequestException("An error occurred while retrieving the user profile.");
                                }

                                var container = JObject.Parse(await response.Content.ReadAsStringAsync());
                                var payload = container["response"].First as JObject;
                    #1#

                    var payload = tokens.Response.Response;
                    var principal = new ClaimsPrincipal(identity);
                    var context = new EHealthOAuthCreatingTicketContext(principal, properties, Context, Scheme, Options, Backchannel, tokens, payload);
                    context.RunClaimActions(payload);

                    //!!!await Options.Events.CreatingTicket(context);
                    return await Task.FromResult(new AuthenticationTicket(context.Principal, context.Properties, Scheme.Name));
                }
        */
        /// <inheritdoc />
        protected override async Task<AuthenticationTicket> CreateTicketAsync([NotNull] ClaimsIdentity identity,
            [NotNull] AuthenticationProperties properties, [NotNull] OAuthTokenResponse tokens)
        {
/*
            var request = new HttpRequestMessage(HttpMethod.Post, Options.UserInformationEndpoint);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", $"{tokens.AccessToken},Id {Options.ClientId}");
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            request.Content = ToJsonContent(new
            {
                type = "physical",
                fields = new[] { "firstName", "middleName", "lastName", "phone", "inn", "clId", "clIdText", "birthDay", "email", "sex", "resident", "dateModification" }
            });

            var response = await Backchannel.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, Context.RequestAborted);
            if (!response.IsSuccessStatusCode)
            {
                Logger.LogError("An error occurred while retrieving the user profile: the remote server " +
                                "returned a {Status} response with the following payload: {Headers} {Body}.",
                                /* Status: #1# response.StatusCode,
                                /* Headers: #1# response.Headers.ToString(),
                                /* Body: #1# await response.Content.ReadAsStringAsync());

                throw new HttpRequestException("An error occurred while retrieving the user profile.");
            }
            var payload = JObject.Parse(await response.Content.ReadAsStringAsync());
*/
            var payload = tokens.Response; 
            var principal = new ClaimsPrincipal(identity);
            var context = new OAuthCreatingTicketContext(principal, properties, Context, Scheme, Options, Backchannel, tokens, payload);

            context.RunClaimActions(payload);

            await Options.Events.CreatingTicket(context);
            return new AuthenticationTicket(context.Principal, context.Properties, Scheme.Name);
        }
    }
}