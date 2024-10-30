using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading.Tasks;
using fileHash;

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
                Console.WriteLine(report.Data.Attributes.LastAnalysisStats);
                return report;
            }
            catch (Exception ex)
            {
                // Log or handle the exception as needed
                Console.WriteLine($"Error fetching report: {ex.Message}");
                return null;
            }
        }
    }
}