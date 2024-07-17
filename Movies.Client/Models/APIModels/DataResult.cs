using Movies.Client.Models.Enumerators;

namespace Movies.Client.Models.APIModels
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
