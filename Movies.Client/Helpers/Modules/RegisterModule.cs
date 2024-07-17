using IdentityModel.Client;
using Movies.Client.APIServices;
using Movies.Client.Helpers.HttpHandler;
using Movies.Client.Helpers.HttpHandler.Interfaces;

namespace Movies.Client.Helpers.Modules
{
    public static class RegisterModule
    {
        public static void RegisterServices(this IServiceCollection services,IConfiguration config)
        {
            services.AddScoped<IMovieAPIService, MovieAPIService>();
            services.AddScoped<IHttpClientRequestHandler, HttpClientRequestHandler>();
            services.AddScoped<APIAuthentication>();
            services.AddTransient<AuthenticationDelegatingHandler>();
            services.AddSingleton(new ClientCredentialsTokenRequest
            {
                Address = config["APICredentials:Address"],
                ClientId = config["APICredentials:ClientId"]!,
                ClientSecret = config["APICredentials:ClientSecret"],
                Scope = config["APICredentials:Scope"]
            });
        }
    }
}
