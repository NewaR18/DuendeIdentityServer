using Movies.Client.Helpers.HttpHandler.Interfaces;
using Movies.Client.Models.APIModels;
using Movies.Client.Models.Enumerators;
using System.Net.Http;
using System.Text;
using System.Text.Json;

namespace Movies.Client.Helpers.HttpHandler
{
    public class HttpClientRequestHandler : IHttpClientRequestHandler
    {
        private readonly IHttpClientFactory _httpClientFactory;
        public HttpClientRequestHandler(IHttpClientFactory httpClientFactory)
        {
            _httpClientFactory = httpClientFactory;
        }
        public async Task<DataResult<T>> CallHttpGet<T>(string Url, string clientName) where T : class
        {
            var apiClient = _httpClientFactory.CreateClient(clientName);
            var request = new HttpRequestMessage(HttpMethod.Get, Url);
            var response = await apiClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead).ConfigureAwait(false);
            //response.EnsureSuccessStatusCode();  throws Exception if the Response is not success
            if (!response.IsSuccessStatusCode)
            {
                return new DataResult<T>
                {
                    ResultType = ResultType.Failed,
                    Message = $"{response.StatusCode} - {response.ReasonPhrase}"
                };
            }
            var content = await response.Content.ReadAsStringAsync();
            return new DataResult<T>
            {
                ResultType = ResultType.Success,
                Data = JsonSerializer.Deserialize<T>(content)!
            };
        }

        public async Task<DataResult> CallHttpPost(string Url, string clientName, dynamic body) => await CallHttp(Url, clientName, body, HttpMethod.Post);
        public async Task<DataResult> CallHttpPut(string Url, string clientName, dynamic body) => await CallHttp(Url, clientName, body, HttpMethod.Put);
        public async Task<DataResult> CallHttpDelete(string Url, string clientName, dynamic body) => await CallHttp(Url, clientName, body, HttpMethod.Delete);

        public async Task<DataResult> CallHttp(string Url, string clientName, dynamic body, HttpMethod httpMethod)
        {
            var apiClient = _httpClientFactory.CreateClient(clientName);
            var request = new HttpRequestMessage(httpMethod, Url);
            request.Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json");
            var response = await apiClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                return new DataResult
                {
                    ResultType = ResultType.Failed,
                    Message = $"{response.StatusCode} - {response.ReasonPhrase}"
                };
            }
            var content = await response.Content.ReadAsStringAsync();
            DataResult dataResult = JsonSerializer.Deserialize<DataResult>(content)!;
            return dataResult;
        }
    }
}
