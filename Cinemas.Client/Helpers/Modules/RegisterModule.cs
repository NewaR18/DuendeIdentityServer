using IdentityModel.Client;
using Cinemas.Client.APIServices;
using Cinemas.Client.Helpers.HttpHandler;
using Cinemas.Client.Helpers.HttpHandler.Interfaces;

namespace Cinemas.Client.Helpers.Modules
{
    public static class RegisterModule
    {
        public static void RegisterServices(this IServiceCollection services,IConfiguration config)
        {
            services.AddScoped<IMovieAPIService, MovieAPIService>();
            services.AddScoped<IHttpClientRequestHandler, HttpClientRequestHandler>();
            services.AddScoped<APIAuthentication>();
            services.AddTransient<AuthenticationDelegatingHandler>();
        }
    }
}
