using Movies.Client.Models;
using Movies.Client.Models.APIModels;

namespace Movies.Client.APIServices
{
    public interface IMovieAPIService
    {
        public Task<DataResult<IEnumerable<Movie>>> GetMovies();
        public Task<DataResult<Movie>> GetMovie(int id);
        public Task<DataResult> CreateMovie(Movie movie);
        public Task<DataResult> UpdateMovie(Movie movie);
        public Task<DataResult> DeleteMovie(int id);
    }
}
