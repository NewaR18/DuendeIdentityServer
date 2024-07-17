
using Microsoft.Extensions.Options;
using Cinemas.Client.Models.APIModels;
using IdentityModel.Client;
using System.Net.Http;
using IdentityModel;
using Microsoft.AspNetCore.Authentication;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Cinemas.Client.Helpers
{
    public class APIAuthentication
    {
        private readonly IConfiguration _config;
        private readonly IHttpContextAccessor _httpContextAccessor;
        public APIAuthentication(IConfiguration config,IHttpContextAccessor httpContextAccessor) 
        {
            _config = config;
            _httpContextAccessor = httpContextAccessor;
        }
        public async Task<bool> IsHealthyIdentityURL(HttpClient client)
        {
            var baseURL = _config["BaseIdentityURL"];
            var discovered = await client.GetDiscoveryDocumentAsync(baseURL);
            if (discovered.IsError)
            {
                return false;
            }
            return true;
        }
        public async Task<TokenResponse> GetAPIAuthenticationToken(HttpClient client, ClientCredentialsTokenRequest apiClientCredentials)
        {
            var tokenResponse = await client.RequestClientCredentialsTokenAsync(apiClientCredentials);
            return tokenResponse;
        }

        public async Task<DiscoveryDocumentResponse> GetDiscoveryDocumentAsync(HttpClient idpClient)
        {
            DiscoveryDocumentResponse discoveryDocument = await idpClient.GetDiscoveryDocumentAsync();
            if (discoveryDocument.IsError)
            {
                throw new Exception();
            }
            return discoveryDocument;
        }

        public async Task<string> GetAccessTokenAsync()
        {
            string? accessToken = await _httpContextAccessor.HttpContext!.GetTokenAsync(OpenIdConnectParameterNames.AccessToken);
            return accessToken!;
		}
		public async Task<UserInfoResponse> GetUserInfoAsync(HttpClient idpClient,UserInfoRequest userInfoRequest)
		{
            UserInfoResponse userInfo = await idpClient.GetUserInfoAsync(userInfoRequest);
            if(userInfo.IsError)
            {
                throw new Exception();
            }
            return userInfo;
		}
	}
}
