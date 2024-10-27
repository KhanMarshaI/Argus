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
        public async Task<JsonResult> GetFileReport(string hash)
        {
            var report = await _virusTotalService.GetFileReportAsync(hash);
            return new JsonResult(report, new JsonSerializerOptions () { WriteIndented = true });
        }

        [HttpGet("url")]
        public async Task<JsonResult> GetUrlReport([FromQuery] string url)
        {
            var report = await _virusTotalService.GetUrlReportAsync(url);
            return new JsonResult(report, new JsonSerializerOptions () { WriteIndented = true });
        }

        [HttpGet("analysis")]
        public async Task<JsonResult> GetAnalysisResultAsync(string analysisID)
        {
            var report = await _virusTotalService.GetAnalysisResultAsync(analysisID);
            return new JsonResult(report, new JsonSerializerOptions() { WriteIndented = true });
        }

        [HttpGet("ip_addresses/{ipAddress}")]
        public async Task<JsonResult> GetIPAddressReportAsync(string ipAddress)
        {
            var report = await _virusTotalService.GetIPAddressReportAsync(ipAddress);
            return new JsonResult(report, new JsonSerializerOptions () { WriteIndented = true });
        }
    }
}
