using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Movies.API.Data;
using Movies.API.Model;
using Movies.API.Models.APIModels;
using Movies.API.Models.Enumerators;
using Movies.API.Utilities;
using System.Text.Json;

namespace Movies.API.Controllers
{
    [Route("api/[controller]/[action]")]
    [ApiController]
    //[Authorize]
    [Authorize("ClientIdPolicy")]
    public class MoviesController : Controller
    {
        private readonly MoviesContext _context;
        private readonly JsonSerializerOptions _serializerOptions;

        public MoviesController(MoviesContext context)
        {
            _context = context;
            _serializerOptions = new JsonSerializerOptions
            {
                WriteIndented = false
            };
        }

        // GET: api/Movies/GetMovies
        [HttpGet]
        public async Task<ActionResult<IEnumerable<Movie>>> GetMovies()
        {
            return new JsonResult(await _context.Movie.ToListAsync(), _serializerOptions);
        }

        // GET: api/Movies/GetMovie/5
        [HttpGet("{id}")]
        public async Task<ActionResult<Movie>> GetMovie(int id)
        {
            var movie = await _context.Movie.FindAsync(id);
            if (movie == null)
            {
                return NotFound();
            }
            return new JsonResult(movie, _serializerOptions);
        }

        // PUT: api/Movies/5
        // To protect from overposting attacks, Use [Bind("Name,Email")] Or Create view model with only properties u want to modify
        [HttpPut("{id}")]
        public async Task<IActionResult> PutMovie(int id, Movie movie)
        {
            if (id != movie.Id)
            {
                return BadRequest();
            }
            _context.Entry(movie).State = EntityState.Modified;
            int state = await _context.SaveChangesAsync();
            if (state > 0)
            {
                return new JsonResult(new DataResult { ResultType = ResultType.Success }, _serializerOptions);
            }
            return new JsonResult(new DataResult
            {
                ResultType = ResultType.Failed,
                Message = Message.UpdateFail
            }, _serializerOptions);
        }

        [HttpPost]
        public async Task<ActionResult<Movie>> PostMovie(Movie movie)
        {
            _context.Movie.Add(movie);
            int state = await _context.SaveChangesAsync();
            if (state > 0)
            {
                return new JsonResult(new DataResult { ResultType= ResultType.Success}, _serializerOptions);
            }
            return new JsonResult(new DataResult { ResultType = ResultType.Failed,
                                                   Message = Message.InsertionFail }, _serializerOptions);
        }

        // DELETE: api/Movies/5
        [HttpDelete("{id}")]
        public async Task<ActionResult<Movie>> DeleteMovie(int id)
        {
            var movie = await _context.Movie.FindAsync(id);
            if (movie == null)
            {
                return new JsonResult(new DataResult
                {
                    ResultType = ResultType.Failed,
                    Message = Message.FetchFail
                }, _serializerOptions);
            }
            _context.Movie.Remove(movie);
            int state = await _context.SaveChangesAsync();
            if (state > 0)
            {
                return new JsonResult(new DataResult { ResultType = ResultType.Success }, _serializerOptions);
            }
            return new JsonResult(new DataResult
            {
                ResultType = ResultType.Failed,
                Message = Message.InsertionFail
            }, _serializerOptions);
        }

        private bool MovieExists(int id)
        {
            return _context.Movie.Any(e => e.Id == id);
        }
    }
}
