using ArgusBackend.Services;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;
using System.Text.Json;
using System.Xml;
using Newtonsoft.Json;

namespace ArgusBackend.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class VirusTotalController : ControllerBase
    {
        private readonly IVirusTotalService _virusTotalService;

        public VirusTotalController(IVirusTotalService virusTotalController)
        {
            _virusTotalService = virusTotalController;
        }

        [HttpGet("file/{hash}")]
        public async Task<IActionResult> GetFileReport(string hash)
        {
            var report = await _virusTotalService.GetFileReportAsync(hash);
            var jsonReport = JsonConvert.DeserializeObject(report);
            var formatJson = JsonConvert.SerializeObject(jsonReport, Newtonsoft.Json.Formatting.Indented);
            return Content(formatJson, "application/json");
        }

        [HttpGet("url")]
        public async Task<IActionResult> GetUrlReport([FromQuery] string url)
        {
            var report = await _virusTotalService.GetUrlReportAsync(url);
            var jsonReport = JsonConvert.DeserializeObject(report);
            var formatJson = JsonConvert.SerializeObject(jsonReport, Newtonsoft.Json.Formatting.Indented);
            return Content(formatJson, "application/json");
        }

        [HttpGet("analysis")]
        public async Task<IActionResult> GetAnalysisResultAsync(string analysisID)
        {
            var report = await _virusTotalService.GetAnalysisResultAsync(analysisID);
            var jsonReport = JsonConvert.DeserializeObject(report);
            var formatJson = JsonConvert.SerializeObject(jsonReport, Newtonsoft.Json.Formatting.Indented);
            return Content(formatJson, "application/json");
        }

        [HttpGet("ip_addresses/{ipAddress}")]
        public async Task<IActionResult> GetIPAddressReportAsync(string ipAddress)
        {
            var report = await _virusTotalService.GetIPAddressReportAsync(ipAddress);
            var jsonReport = JsonConvert.DeserializeObject(report);
            var formatJson = JsonConvert.SerializeObject(jsonReport, Newtonsoft.Json.Formatting.Indented);
            return Content(formatJson, "application/json");
        }
    }
}
