using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using static IdentityModel.OidcConstants;

namespace Movies.Client.Helpers.HttpHandler
{
    public class AuthenticationDelegatingHandler : DelegatingHandler
    {
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly ClientCredentialsTokenRequest _tokenRequest;
        private readonly IHttpContextAccessor _httpContextAccessor;
        public AuthenticationDelegatingHandler(IHttpClientFactory httpClientFactory, ClientCredentialsTokenRequest tokenRequest, IHttpContextAccessor httpContextAccessor)
        {
            _httpClientFactory = httpClientFactory;
            _tokenRequest = tokenRequest;
            _httpContextAccessor = httpContextAccessor;
        }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var accessToken = await _httpContextAccessor.HttpContext!.GetTokenAsync(OpenIdConnectParameterNames.AccessToken);
            if(!string.IsNullOrEmpty(accessToken))
                request.SetBearerToken(accessToken!);

            //var idToken = await _httpContextAccessor.HttpContext!.GetTokenAsync(OpenIdConnectParameterNames.IdToken);

            #region Hitting API -old and slow method
            //Getting Access Token hitting API
            //var httpClient = _httpClientFactory.CreateClient("IdentityServerClient");
            //var tokenResponse = await httpClient.RequestClientCredentialsTokenAsync(_tokenRequest);
            //if (tokenResponse.IsError)
            //{
            //    throw new HttpRequestException("Something wrong while getting Client Credentials Token from IdentityServer");
            //}
            //request.SetBearerToken(tokenResponse.AccessToken!);
            #endregion

            return await base.SendAsync(request, cancellationToken);
        }
    }
}
