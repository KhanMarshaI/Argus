using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using RestSharp;
using Newtonsoft.Json;
using System.Net;
using Microsoft.AspNetCore.WebUtilities;

namespace ArgusBackend.Services
{
    public class VirusTotalService : IVirusTotalService
    {
        private readonly HttpClient _httpClient;
        private readonly string _apiKey;

        public VirusTotalService(HttpClient httpClient, IConfiguration configuration)
        {
            _httpClient = httpClient;
            _apiKey = configuration["VirusTotal:ApiKey"];
        }

        public async Task<string> GetFileReportAsync(string hash)
        {
            var options = new RestClientOptions($"https://www.virustotal.com/api/v3/files/{hash}");
            var client = new RestClient(options);
            var request = new RestRequest("");
            request.AddHeader("accept", "application/json");
            request.AddHeader("x-apikey", _apiKey);
            var response = await client.GetAsync(request);

            return response.Content;
        }

        public async Task<string> GetUrlReportAsync(string url)
        {
            var options = new RestClientOptions($"https://www.virustotal.com/api/v3/urls");
            var client = new RestClient(options);
            var request = new RestRequest("");
            request.AddHeader("accept", "application/json");
            request.AddHeader("x-apikey", _apiKey);
            request.AddParameter("url", url);
            var response = await client.PostAsync(request);

            return response.Content;
        }

        public async Task<string> GetAnalysisResultAsync(string analysisID)
        {
            var options = new RestClientOptions($"https://www.virustotal.com/api/v3/analyses/{analysisID}");
            var client = new RestClient(options);
            var request = new RestRequest("");
            request.AddHeader("accept", "application/json");
            request.AddHeader("x-apikey", _apiKey);
            var response = await client.GetAsync(request);

            return response.Content;
        }

        public async Task<string> GetIPAddressReportAsync(string ipAddress)
        {
            var options = new RestClientOptions($"https://www.virustotal.com/api/v3/ip_addresses/{ipAddress}");
            var client = new RestClient(options);
            var request = new RestRequest("");
            request.AddHeader("accept", "application/json");
            request.AddHeader("x-apikey", _apiKey);
            var response = await client.GetAsync(request);

            return response.Content;
        }

        public async Task<string> UploadFileAsync(byte[] fileBytes, string fileName)
        {
            var client = new RestClient("https://www.virustotal.com/api/v3/files");
            var request = new RestRequest("", Method.Post);
            request.AddHeader("x-apikey", _apiKey);
            request.AddHeader("accept", "application/json");
            request.AlwaysMultipartFormData = true;
            request.AddFile("file", fileBytes, fileName);

            var response = await client.ExecuteAsync(request);
            return response.Content;
        }
    }
}
