using System.Net.Http;
using System.Net.Http.Json;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using fileHash;
using URLAnalysis;
using _Analysis;
using FileAnalysis;

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
                Console.WriteLine($"Error fetching hash report API: {ex.Message}");
                return null;
            }
        }

		public async Task<URLRep> UploadFileAsync(Stream fileStream, string fileName)
		{
			try
			{
				using var content = new MultipartFormDataContent();
				content.Add(new StreamContent(fileStream), "file", fileName);

				var response = await _httpClient.PostAsync("api/VirusTotal/fileUpload", content);
				response.EnsureSuccessStatusCode();

				var responseBody = await response.Content.ReadAsStringAsync();

                var report = await response.Content.ReadFromJsonAsync<URLRep>(_jsonOptions);
                return report;
			}
			catch (Exception ex)
			{
				Console.WriteLine($"Error uploading file: {ex.Message}");
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
                Console.WriteLine($"Error fetching url report API: {ex.Message}");
                return null;
            }
        }

        public async Task<Analysis> GetAnalysisAsync(string analysisID)
        {
            try
            {
                var request = new HttpRequestMessage
                {
                    Method = HttpMethod.Get,
                    RequestUri = new Uri($"https://localhost:7220/api/VirusTotal/analysis?analysisID={Uri.EscapeDataString(analysisID)}"),
                    Headers =
                   {
                       { "accept" ,"*/*" }
                   }
                };

                using (var response = await _httpClient.SendAsync(request))
                {
                    response.EnsureSuccessStatusCode();
                    var body = await response.Content.ReadFromJsonAsync<Analysis>(_jsonOptions);
                    return body;
                }
            }
            catch (Exception ex)
            {
                // Log or handle the exception as needed
                Console.WriteLine($"Error fetching analysis report API: {ex.Message}");
                return null;
            }
        }

        public async Task<FileUploadAnalysis> GetFileAnalysisAsync(string analysisID)
        {
            try
            {
                var request = new HttpRequestMessage
                {
                    Method = HttpMethod.Get,
                    RequestUri = new Uri($"https://localhost:7220/api/VirusTotal/analysis?analysisID={analysisID}"),
                    Headers =
                   {
                       { "accept" ,"*/*" }
                   }
                };

                using (var response = await _httpClient.SendAsync(request))
                {
                    response.EnsureSuccessStatusCode();
                    var body = await response.Content.ReadFromJsonAsync<FileUploadAnalysis>(_jsonOptions);
                    return body;
                }
            }
            catch (Exception ex)
            {
                // Log or handle the exception as needed
                Console.WriteLine($"Error fetching analysis report API: {ex.Message}");
                return null;
            }
        }

    }
}