using Cinemas.Client.Models;
using Cinemas.Client.Models.APIModels;
using Cinemas.Client.Models.ViewModels;

namespace Cinemas.Client.APIServices
{
    public interface IMovieAPIService
    {
        Task<DataResult<IEnumerable<Movie>>> GetMovies();
        Task<DataResult<Movie>> GetMovie(int id);
        Task<DataResult> CreateMovie(Movie movie);
        Task<DataResult> UpdateMovie(Movie movie);
        Task<DataResult> DeleteMovie(int id);
        Task<UserInfoViewModel> getUserInfo();
    }
}
