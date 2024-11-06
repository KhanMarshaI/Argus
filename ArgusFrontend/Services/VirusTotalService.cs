using System.Net.Http;
using System.Net.Http.Json;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using fileHash;
using URLAnalysis;

namespace ArgusFrontend.Services
{
    public class VirusTotalService
    {
        private readonly HttpClient _httpClient;
        private readonly JsonSerializerOptions _jsonOptions;

        public VirusTotalService(HttpClient httpClient)
        {
            _httpClient = httpClient;
            _jsonOptions = new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            };
        }

        public async Task<Hash> GetFileHashReportAsync(string hash)
        {
            try
            {
                // Attempt to retrieve the JSON response from the API
                var response = await _httpClient.GetAsync($"api/VirusTotal/file/{hash}");
                response.EnsureSuccessStatusCode();

                // Print the raw JSON response
                var responseBody = await response.Content.ReadAsStringAsync();

                // Deserialize the JSON response
                var report = await response.Content.ReadFromJsonAsync<Hash>(_jsonOptions);
                return report;
            }
            catch (Exception ex)
            {
                // Log or handle the exception as needed
                Console.WriteLine($"Error fetching report: {ex.Message}");
                return null;
            }
        }

        public async Task<URLRep> GetURLReport(string url)
        {
            try
            {
                var request = new HttpRequestMessage
                {
                    Method = HttpMethod.Post,
                    RequestUri = new Uri($"https://localhost:7220/api/VirusTotal/url?url={Uri.EscapeDataString(url)}"),
                    Headers =
                    {
                        { "accept", "application/json" },
                    }
                };

                using (var response = await _httpClient.SendAsync(request))
                {
                    response.EnsureSuccessStatusCode();
                    var body = await response.Content.ReadFromJsonAsync<URLRep>(_jsonOptions);
                    return body;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error fetching report: {ex.Message}");
                return null;
            }
        }


    }
}