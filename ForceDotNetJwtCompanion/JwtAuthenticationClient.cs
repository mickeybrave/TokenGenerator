using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using ForceDotNetJwtCompanion.Models;
using ForceDotNetJwtCompanion.Util;
using Newtonsoft.Json;

namespace ForceDotNetJwtCompanion
{
    /// <summary>
    /// IJwtAuthenticationClient
    ///
    /// HTTP handling and orchestration of JWT OAuth Flow with Salesforce.
    /// 
    /// </summary>
    public interface IJwtAuthenticationClient : IDisposable
    {
        string InstanceUrl { get; set; }
        string AccessToken { get; set; }
        string Id { get; set; }
        string ApiVersion { get; set; }
        string JWT { get; set; }

       
        /// <summary>
        /// JwtPrivateKeyAsync
        ///
        /// Obtain access token with encrypted private key
        /// with token endpoint
        /// </summary>
        /// <param name="clientId">ClientId of the Connected App aka Consumer Key</param>
        /// <param name="privateKey">Private key as string, it is not required to remove header and footer</param>
        /// <param name="clientSecret">Passphrase of the private key or clientSecret</param>
        /// <param name="username">Salesforce username</param>
        /// <param name="tokenEndpoint">TokenEndpointUrl e.g. https://test.salesforce.com/services/oauth2/token</param>
        Task JwtPrivateKeyAsync(string clientId, string privateKey, string clientSecret, string username, string tokenEndpoint);

        /// <summary>
        /// clientId, privateKey and secret are set in the content of post response
        /// </summary>
        /// <param name="clientId">ClientId of the Connected App aka Consumer Key</param>
        /// <param name="privateKey">Private key as string, it is not required to remove header and footer</param>
        /// <param name="clientSecret">Passphrase of the private key or clientSecret</param>
        /// <param name="username">Salesforce username</param>
        /// <param name="tokenEndpoint">TokenEndpointUrl e.g. https://test.salesforce.com/services/oauth2/token</param>
        /// <returns></returns>
        Task JwtPrivateKeyByClientIdAsync(string clientId, string privateKey, string clientSecret, string username, string tokenEndpoint);
    }

    public class JwtAuthenticationClient : IJwtAuthenticationClient
    {
        public string InstanceUrl { get; set; }
        public string AccessToken { get; set; }
        public string JWT { get; set; }
        public string Id { get; set; }
        public string ApiVersion { get; set; }

        private const string UserAgent = "forcedotnet-jwt-companion";
        private const string TokenRequestEndpointUrl = "https://login.salesforce.com/services/oauth2/token";
        private const string GrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer";
        private const string ProdAudience = "https://login.salesforce.com";
        private const string RedirectLoginUri = "https://login.salesforce.com";
        private const string TestAudience = "https://test.salesforce.com";

        private readonly HttpClient _httpClient;
        private readonly bool _disposeHttpClient;
        private readonly bool _isProd;

        public JwtAuthenticationClient(
            string apiVersion = "v50.0",
            bool isProd = true
            ) : this(new HttpClient(), apiVersion: apiVersion, isProd: isProd)
        {
        }

        public JwtAuthenticationClient(
            HttpClient httpClient,
            string apiVersion = "v50.0",
            bool callerWillDisposeHttpClient = false,
            bool isProd = true
            )
        {

            _httpClient = httpClient ?? throw new ArgumentException("httpClient");
            _disposeHttpClient = !callerWillDisposeHttpClient;
            ApiVersion = apiVersion;
            _isProd = isProd;
        }

        #region IJwtAuthenticationClient
        public async Task JwtPrivateKeyByClientIdAsync(string clientId, string privateKey, string clientSecret, string username, string tokenEndpoint)
        {
            JWT = CreateJwt(
                   clientId,
                   KeyHelpers.CreatePrivateKeyWrapperWithPassPhrase(privateKey, clientSecret),
                   username,
                   _isProd ? ProdAudience : TestAudience);

            (Id, InstanceUrl, AccessToken) = await CallTokenEndpoint(JWT,
                clientId,
                clientSecret,
                tokenEndpoint
            );
        }

        public async Task JwtPrivateKeyAsync(string clientId, string privateKey, string clientSecret, string username, string tokenEndpoint)
        {
            JWT = CreateJwt(
                    clientId,
                    KeyHelpers.CreatePrivateKeyWrapperWithPassPhrase(privateKey, clientSecret),
                    username, _isProd ? ProdAudience : TestAudience);

            (Id, InstanceUrl, AccessToken) = await CallTokenEndpoint(JWT, tokenEndpoint);

        }
        #endregion

        #region Private Methods
        private string CreateJwt(string clientId, PrivateKeyWrapper keyWrapper, string username, string audience) =>
          Jwt.Jwt.CreateJwt(keyWrapper)
              .AddExpiration(DateTime.UtcNow)
              .AddSubject(username)
              .AddAudience(audience)
              .AddConsumerKey(clientId)
              .Build();

        private async Task<AuthToken> CallTokenEndpoint(string jwt, string clientId, string clientSecret, string tokenEndpoint)
        {
            var request = new HttpRequestMessage
            {
                Method = HttpMethod.Post,
                RequestUri = new Uri(tokenEndpoint),
                Content = new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string, string>("grant_type", GrantType),
                    new KeyValuePair<string, string>("client_id", clientId),
                    new KeyValuePair<string, string>("client_secret", clientSecret),
                    new KeyValuePair<string, string>("redirect_uri", RedirectLoginUri),
                    new KeyValuePair<string, string>("assertion", jwt)
                })
            };
            request.Headers.UserAgent.ParseAdd(string.Concat(UserAgent, "/", ApiVersion));

            HttpResponseMessage responseMessage;

            return await BuildResponse(request);
        }

        private async Task<AuthToken> CallTokenEndpoint(string jwt, string tokenEndpoint)
        {
            var request = new HttpRequestMessage
            {
                Method = HttpMethod.Post,
                RequestUri = new Uri(tokenEndpoint),
                Content = new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string, string>("grant_type", GrantType),
                    new KeyValuePair<string, string>("assertion", jwt)
                })
            };
            request.Headers.UserAgent.ParseAdd(string.Concat(UserAgent, "/", ApiVersion));
            return await BuildResponse(request);
           
        }


        private async Task<AuthToken> BuildResponse(HttpRequestMessage request)
        {
            HttpResponseMessage responseMessage;

            try
            {
                responseMessage = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseContentRead);
            }
            catch (Exception exc)
            {
                throw new ForceAuthenticationException(HttpStatusCode.InternalServerError, exc.Message);
            }

            if (responseMessage.IsSuccessStatusCode)
            {
                var stringResult = await responseMessage.Content.ReadAsStringAsync();
                var authToken = JsonConvert
                    .DeserializeObject<AuthToken>(stringResult);
                return authToken;
            }

            try
            {
                var stringError = await responseMessage.Content.ReadAsStringAsync();
                var errorResponse = JsonConvert
                    .DeserializeObject<AuthErrorResponse>(stringError);
                throw new ForceAuthenticationException(
                    responseMessage.StatusCode,
                    $"{errorResponse.Error}: {errorResponse.ErrorDescription}"
                );
            }
            catch (Exception exc)
            {
                throw new ForceAuthenticationException(HttpStatusCode.InternalServerError, exc.Message);
            }

        }
        #endregion

        #region IDisposable
        public void Dispose()
        {
            if (_disposeHttpClient)
            {
                _httpClient?.Dispose();
            }
        }
        #endregion

    }
}