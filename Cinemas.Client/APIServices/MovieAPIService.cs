using IdentityModel.Client;
using Cinemas.Client.Helpers;
using Cinemas.Client.Helpers.HttpHandler.Interfaces;
using Cinemas.Client.Models;
using Cinemas.Client.Models.APIModels;
using Cinemas.Client.Models.ViewModels;
using System.Net.Http;

namespace Cinemas.Client.APIServices
{
    public class MovieAPIService : IMovieAPIService
    {
        private readonly APIAuthentication _aPIAuthentication;
        private readonly IHttpClientRequestHandler _httpClient;
        private readonly IHttpClientFactory _httpClientFactory;
        public MovieAPIService(IHttpClientRequestHandler httpClient, APIAuthentication aPIAuthentication,IHttpClientFactory httpClientFactory)
        {
            _httpClient = httpClient;
            _aPIAuthentication = aPIAuthentication;
            _httpClientFactory = httpClientFactory;
        }
        public async Task<DataResult> CreateMovie(Movie movie)
        {
            DataResult dataResult = await _httpClient.CallHttpPost(APIGateway.PostMovies, APIClients.MoviesClient,movie);
            return dataResult;
        }
        public async Task<DataResult<IEnumerable<Movie>>> GetMovies()
        {
            DataResult<IEnumerable<Movie>> movies = await _httpClient.CallHttpGet<IEnumerable<Movie>>(APIGateway.GetMovies, APIClients.MoviesClient);
            return movies;
        }
        public async Task<DataResult<Movie>> GetMovie(int id)
        {
            var callUrl = $"{APIGateway.GetMovieById}/{id}";
            DataResult<Movie> movie = await _httpClient.CallHttpGet<Movie>(callUrl, APIClients.MoviesClient);
            return movie;
        }
        public async Task<DataResult> UpdateMovie(Movie movie)
        {
            var callUrl = $"{APIGateway.UpdateMovies}/{movie.Id}";
            DataResult dataResult = await _httpClient.CallHttpPut(callUrl, APIClients.MoviesClient, movie);
            return dataResult;
        }
        public async Task<DataResult> DeleteMovie(int Id)
        {
            var callUrl = $"{APIGateway.DeleteMovies}/{Id}";
            DataResult dataResult = await _httpClient.CallHttpDelete(callUrl, APIClients.MoviesClient,Id);
            return dataResult;
        }
        public async Task<UserInfoViewModel> getUserInfo()
        {
			HttpClient idpClient = _httpClientFactory.CreateClient(APIClients.IdentityServerClient);
			DiscoveryDocumentResponse discoveryDocument = await _aPIAuthentication.GetDiscoveryDocumentAsync(idpClient);
            var accessToken = await _aPIAuthentication.GetAccessTokenAsync();
            UserInfoRequest userInfoRequest = new UserInfoRequest()
            {
                Address = discoveryDocument.UserInfoEndpoint,
                Token = accessToken
            };
            UserInfoResponse userInfoResponse = await _aPIAuthentication.GetUserInfoAsync(idpClient, userInfoRequest);
            var userInfoDictionary = new Dictionary<string, string>();
            foreach(var claim in userInfoResponse.Claims)
            {
                userInfoDictionary.Add(claim.Type,claim.Value);
			}
            return new UserInfoViewModel(userInfoDictionary);
        }
    }
}
