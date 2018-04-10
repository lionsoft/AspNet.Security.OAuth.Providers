using System;
using Microsoft.AspNetCore.Authentication.OAuth;
using Newtonsoft.Json.Linq;

namespace AspNet.Security.OAuth.EHealth
{
    public class EHealthOAuthTokenResponse
    {
        private EHealthOAuthTokenResponse(JObject response)
        {
            var data = response.Value<JObject>("data");
            AccessToken = data?.Value<string>("value");
            TokenType = data?.Value<string>("name");
            ExpiresIn = data?.Value<string>("expires_at");
            Id = data?.Value<string>("id");
            UserId = data?.Value<string>("user_id");
            var details = data?.Value<JObject>("details");
            RefreshToken = details?.Value<string>("refresh_token");
            Scope = details?.Value<string>("scope");

            Response = OAuthTokenResponse.Success(data ?? response);
            Response.AccessToken = Response.AccessToken ?? AccessToken;
            Response.TokenType = Response.TokenType ?? TokenType;
            Response.ExpiresIn = Response.ExpiresIn ?? ExpiresIn;
            Response.RefreshToken = Response.RefreshToken ?? RefreshToken;

            AccessToken = Response.AccessToken;
            TokenType = Response.TokenType;
            ExpiresIn = Response.ExpiresIn;
            RefreshToken = Response.RefreshToken;
        }

        private EHealthOAuthTokenResponse(Exception error)
        {
            Error = error;
            Response = OAuthTokenResponse.Failed(error);
        }

        public static EHealthOAuthTokenResponse Success(JObject response)
        {
            return new EHealthOAuthTokenResponse(response);
        }

        public static EHealthOAuthTokenResponse Failed(Exception error)
        {
            return new EHealthOAuthTokenResponse(error);
        }

        public OAuthTokenResponse Response { get; set; }

        public string AccessToken { get; set; }

        public string TokenType { get; set; }

        public string RefreshToken { get; set; }

        public string ExpiresIn { get; set; }

        public string UserId { get; set; }

        public string Id { get; set; }

        public string Scope { get; set; }

        public Exception Error { get; set; }
    }
}