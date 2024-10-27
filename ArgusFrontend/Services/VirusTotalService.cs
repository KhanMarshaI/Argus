using System.Net.Http;
using System.Net.Http.Json;
using System.Threading.Tasks;
using fileHash;

namespace ArgusFrontend.Services
{
    public class VirusTotalService
    {
        private readonly HttpClient _httpClient; 

        public VirusTotalService(HttpClient httpClient)
        {
            _httpClient = httpClient;
        }

        public async Task<Hash> GetFileHashReportAsync(string hash)
        {
            return await _httpClient.GetFromJsonAsync<Hash>($"api/VirusTotal/file/{hash}");
        }
    }
}
