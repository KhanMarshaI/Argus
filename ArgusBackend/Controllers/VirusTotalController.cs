using ArgusBackend.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;
using System.Text.Json;
using System.Xml;
using System.IO;
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

        [HttpPost("fileUpload")]
        public async Task<IActionResult> UploadFile(IFormFile file)
        {
            if (file == null || file.Length == 0)
            {
                return BadRequest("No file uploaded or file is empty.");
            }
            await using var memoryStream = new MemoryStream();
            await file.CopyToAsync(memoryStream);
            var fileBytes = memoryStream.ToArray();

            var response = await _virusTotalService.UploadFileAsync(fileBytes, file.FileName);
            var jsonReport = JsonConvert.DeserializeObject(response);
            var formatJson = JsonConvert.SerializeObject(jsonReport, Newtonsoft.Json.Formatting.Indented);
            return Content(formatJson, "application/json");
        }

        [HttpGet("file/{hash}")]
        public async Task<IActionResult> GetFileReport(string hash)
        {
            var report = await _virusTotalService.GetFileReportAsync(hash);
            var jsonReport = JsonConvert.DeserializeObject(report);
            var formatJson = JsonConvert.SerializeObject(jsonReport, Newtonsoft.Json.Formatting.Indented);
            return Content(formatJson, "application/json");
        }

        [HttpPost("url")]
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
