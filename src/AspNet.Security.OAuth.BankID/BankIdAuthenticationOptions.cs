/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Http;

namespace AspNet.Security.OAuth.BankId
{
    /// <summary>
    /// Defines a set of options used by <see cref="BankIdAuthenticationHandler"/>.
    /// </summary>
    public class BankIdAuthenticationOptions : OAuthOptions
    {
        public BankIdAuthenticationOptions()
        {
            ClaimsIssuer = BankIdAuthenticationDefaults.Issuer;

            CallbackPath = new PathString(BankIdAuthenticationDefaults.CallbackPath);

            IsSandBox = false;
            ClaimActions.MapCustomJson(ClaimTypes.NameIdentifier, user => Decode(user["customer"]["clId"]));
            ClaimActions.MapCustomJson(ClaimTypes.Name, user => $"{Decode(user["customer"]["lastName"])} {Decode(user["customer"]["firstName"])} {Decode(user["customer"]["middleName"])}".Trim());
            ClaimActions.MapCustomJson(ClaimTypes.Email, user => Decode(user["customer"]["email"]));
            ClaimActions.MapCustomJson(ClaimTypes.MobilePhone, user => Decode(user["customer"]["phone"]));
            ClaimActions.MapCustomJson(ClaimTypes.DateOfBirth, user => Decode(user["customer"]["birthDay"]));
            ClaimActions.MapCustomJson("urn:BankId:clIdText", user => Decode(user["customer"]["clIdText"]));
            ClaimActions.MapCustomJson("urn:BankId:lastName", user => Decode(user["customer"]["lastName"]));
            ClaimActions.MapCustomJson("urn:BankId:firstName", user => Decode(user["customer"]["firstName"]));
            ClaimActions.MapCustomJson("urn:BankId:middleName", user => Decode(user["customer"]["middleName"]));
            ClaimActions.MapCustomJson("urn:BankId:sex", user => Decode(user["customer"]["sex"]));
            ClaimActions.MapCustomJson("urn:BankId:resident", user => Decode(user["customer"]["resident"]));
            ClaimActions.MapCustomJson("urn:BankId:dateModification", user => Decode(user["customer"]["dateModification"]));
        }

        public bool IsSandBox
        {
            get => AuthorizationEndpoint == BankIdAuthenticationDefaults.SandboxAuthorizationEndpoint;
            set
            {
                if (!value)
                {
                    AuthorizationEndpoint = BankIdAuthenticationDefaults.AuthorizationEndpoint;
                    TokenEndpoint = BankIdAuthenticationDefaults.TokenEndpoint;
                    UserInformationEndpoint = BankIdAuthenticationDefaults.UserInformationEndpoint;
                }
                else
                {
                    AuthorizationEndpoint = BankIdAuthenticationDefaults.SandboxAuthorizationEndpoint;
                    TokenEndpoint = BankIdAuthenticationDefaults.SandboxTokenEndpoint;
                    UserInformationEndpoint = BankIdAuthenticationDefaults.SandboxUserInformationEndpoint;
                }
            }
        }

        /// <summary>
        /// Path to X509Certificate2 .pfx file.
        /// </summary>
        public string CertificateFileName { get; set; }

        /// <summary>
        /// X509Certificate2 to decode data.
        /// </summary>
        public X509Certificate2 Certificate { get; set; }

        private string Decode(object value)
        {
            if (Certificate == null && CertificateFileName != null)
            {
                Certificate = new X509Certificate2(CertificateFileName);
            }

            if (Certificate == null)
            {
                throw new Exception("Set correct value of the Certificate or CertificateFileName properties in the BankIdAuthenticationOptions.");
            }
            var encodedBytes = Convert.FromBase64String(value.ToString());
            var rsa = (RSACryptoServiceProvider) Certificate.PrivateKey;
            var dres = rsa.Decrypt(encodedBytes, false);
            var res = Encoding.UTF8.GetString(dres);
            return res;
        }
    }
}
