using Cinemas.Client.Models.APIModels;

namespace Cinemas.Client.Helpers.HttpHandler.Interfaces
{
    public interface IHttpClientRequestHandler
    {
        Task<DataResult<T>> CallHttpGet<T>(string Url, string clientName) where T : class;
        Task<DataResult> CallHttpPost(string Url, string clientName, dynamic body);
        Task<DataResult> CallHttpPut(string Url, string clientName, dynamic body);
        Task<DataResult> CallHttpDelete(string Url, string clientName, dynamic body);
    }
}
