using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Cinemas.Client.Helpers.HttpHandler
{
    public class AuthenticationDelegatingHandler : DelegatingHandler
    {
        private readonly IHttpContextAccessor _httpContextAccessor;
        public AuthenticationDelegatingHandler(IHttpContextAccessor httpContextAccessor)
        {
            _httpContextAccessor= httpContextAccessor;
        }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var tokenResponse = await _httpContextAccessor.HttpContext!.GetTokenAsync(OpenIdConnectParameterNames.AccessToken);
            if (!string.IsNullOrEmpty(tokenResponse))
            {
                request.SetBearerToken(tokenResponse!);
            }
            return await base.SendAsync(request, cancellationToken);
        }
    }
}
