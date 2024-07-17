using IdentityModel.Client;
using Microsoft.Extensions.Options;
using Movies.Client.Models.APIModels;

namespace Movies.Client.Helpers
{
    public class APIAuthentication
    {
        private readonly IOptions<APICredentials> _options;
        private readonly IConfiguration _config;
        public APIAuthentication(IOptions<APICredentials> options, IConfiguration config) 
        {
            _options = options;
            _config = config;
        }

        public ClientCredentialsTokenRequest GetAPICredentials()
        {
            return new ClientCredentialsTokenRequest
            {
                Address = _options.Value.Address,
                ClientId = _options.Value.ClientId,
                ClientSecret = _options.Value.ClientSecret,
                Scope = _options.Value.Scope
            };
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
    }
}
