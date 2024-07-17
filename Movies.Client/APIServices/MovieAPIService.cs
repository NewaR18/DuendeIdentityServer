using Movies.Client.Helpers;
using Movies.Client.Helpers.HttpHandler.Interfaces;
using Movies.Client.Models;
using Movies.Client.Models.APIModels;

namespace Movies.Client.APIServices
{
    public class MovieAPIService : IMovieAPIService
    {
        //private readonly IAPIRequest _aPIRequest;
        private readonly IHttpClientRequestHandler _httpClient;

        public MovieAPIService(IHttpClientRequestHandler httpClient)
        {
            _httpClient = httpClient;
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
    }
}
