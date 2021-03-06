/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using AspNet.Security.OAuth.BankId;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace Mvc.Client
{
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddAuthentication(options =>
            {
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            })

            .AddCookie(options =>
            {
                options.LoginPath = "/login";
                options.LogoutPath = "/signout";
            })

            .AddBankId(options =>
            {
                options.ClientId = "7c421c90-1818-4e5c-b20f-7a83d6940102";
                options.ClientSecret = "Mjg1OGJmYWYtZjZiNC00YTJiLTk5YzAtOTY3MzUxMjM3ZWJk";
                //options.IsSandBox = true;
                options.CertificateFileName = "D:\\Dropbox\\Sync\\OblRada\\rsa_key.pfx";
            })

            .AddEHealth(options =>
            {
                options.ClientId = "2940f64b-bcc2-42b0-bb32-48e2deea33b4";
                options.ClientSecret = "UUdYTUVtOStrZEh1RUVUaWRxTDdDZz09";
                options.RedirectUri = "http://onko.mdsoft.com.ua";
                options.SaveTokens = true;
            })

            .AddGoogle(options =>
            {
                options.ClientId = "560027070069-37ldt4kfuohhu3m495hk2j4pjp92d382.apps.googleusercontent.com";
                options.ClientSecret = "n2Q-GEw9RQjzcRbU3qhfTj8f";
            })

            .AddTwitter(options =>
            {
                options.ConsumerKey = "6XaCTaLbMqfj6ww3zvZ5g";
                options.ConsumerSecret = "Il2eFzGIrYhz6BWjYhVXBPQSfZuS4xoHpSSyD9PI";
            })

            .AddGitHub(options =>
            {
                options.ClientId = "49e302895d8b09ea5656";
                options.ClientSecret = "98f1bf028608901e9df91d64ee61536fe562064b";
                options.Scope.Add("user:email");
            });

            services.AddMvc();
        }

        public void Configure(IApplicationBuilder app)
        {
            app.UseStaticFiles();

            app.UseAuthentication();

            app.UseMvc();
        }
    }
}