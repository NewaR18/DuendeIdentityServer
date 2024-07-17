using Cinemas.Client.APIServices;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Cinemas.Client.Helpers.Utilities;
using Cinemas.Client.Models;
using Cinemas.Client.Models.APIModels;
using Cinemas.Client.Models.Enumerators;
using Microsoft.AspNetCore.Authentication;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System.Diagnostics;
using Cinemas.Client.Models.ViewModels;
namespace Cinemas.Client.Controllers
{
    [Authorize]
    public class CinemasController : Controller
    {
        private readonly IMovieAPIService _service;

        public CinemasController(IMovieAPIService service)
        {
            _service = service;
        }
        [Authorize(Roles = nameof(Roles.admin))]
        public async Task<IActionResult> AdminIndex()
        {
            UserInfoViewModel userInfo = await _service.getUserInfo();
            return View(userInfo);
        }
        public async Task<IActionResult> Index()
        {
            await GetTokenAndClaims();
            DataResult<IEnumerable<Movie>> movies = await _service.GetMovies();
            if (movies.ResultType.Equals(ResultType.Success))
            {
                return View(movies.Data);
            }
            TempData[nameof(Status.Error)] = Message.FetchFail;
            return View(new List<Movie>());
        }

        public async Task<IActionResult> Details(int id)
        {
            DataResult<Movie> movies = await _service.GetMovie(id);
            if (movies.ResultType.Equals(ResultType.Success))
            {
                return View(movies.Data);
            }
            TempData[nameof(Status.Error)] = Message.FetchFail;
            return View(new Movie());
        }

        public IActionResult Create()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(Movie movie)
        {
            if (ModelState.IsValid)
            {
                DataResult result = await _service.CreateMovie(movie);
                if (result.ResultType.Equals(ResultType.Success))
                {
                    TempData[nameof(Status.Success)] = Message.CreationSuccess;
                    return RedirectToAction(nameof(Index));
                }
                TempData[nameof(Status.Error)] = Message.CreationFail;
                return View(movie);
            }
            return View(movie);
        }

        public async Task<IActionResult> Edit(int id)
        {
            DataResult<Movie> movies = await _service.GetMovie(id);
            if (movies.ResultType.Equals(ResultType.Success))
            {
                return View(movies.Data);
            }
            TempData[nameof(Status.Error)] = Message.FetchFail;
            return RedirectToAction(nameof(Index));
        }

        // To protect from overposting attacks, Use [Bind("Name,Email")] Or Create view model with only properties u want to modify
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(Movie movie)
        {
            if (movie.Id.Equals(0))
            {
                TempData[nameof(Status.Error)] = Message.IdNotPassed;
                return View(movie);
            }
            if (ModelState.IsValid)
            {
                DataResult result = await _service.UpdateMovie(movie);
                if (result.ResultType.Equals(ResultType.Success))
                {
                    TempData[nameof(Status.Success)] = Message.UpdateSuccess;
                    return RedirectToAction(nameof(Index));
                }
                TempData[nameof(Status.Error)] = Message.UpdateFail;
                return View(movie);
            }
            return View(movie);
        }

        // GET: Movies/Delete/5
        public async Task<IActionResult> Delete(int id)
        {
            DataResult<Movie> movies = await _service.GetMovie(id);
            if (movies.ResultType.Equals(ResultType.Success))
            {
                return View(movies.Data);
            }
            TempData[nameof(Status.Error)] = Message.FetchFail;
            return RedirectToAction(nameof(Index));
        }

        // POST: Movies/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int Id)
        {
            if (Id.Equals(0))
            {
                TempData[nameof(Status.Error)] = Message.IdNotPassed;
                return RedirectToAction(nameof(Index));
            }
            DataResult result = await _service.DeleteMovie(Id);
            if (result.ResultType.Equals(ResultType.Success))
            {
                TempData[nameof(Status.Success)] = Message.DeleteSuccess;
                return RedirectToAction(nameof(Index));
            }
            TempData[nameof(Status.Error)] = Message.UpdateFail;
            return RedirectToAction(nameof(Index));
        }

        public async Task GetTokenAndClaims()
        {
            var identityToken = await HttpContext.GetTokenAsync(OpenIdConnectParameterNames.IdToken);
            Debug.WriteLine("Id Token: " + identityToken);
            foreach (var claim in User.Claims)
            {
                Debug.WriteLine($"Claim type: {claim.Type} - Claim value: {claim.Value}");
            }
        }
    }
}
