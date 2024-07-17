using Movies.API.Models.Enumerators;

namespace Movies.API.Models.APIModels
{
    public class DataResult<T> where T: class
    {
        public ResultType ResultType { get; set; }
        public string Message { get; set; }
        public T Data { get; set; }
    }
    public class DataResult 
    {
        public ResultType ResultType { get; set; }
        public string Message { get; set; }
    }
}
