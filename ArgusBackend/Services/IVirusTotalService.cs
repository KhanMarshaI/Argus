namespace ArgusBackend.Services
{
    public interface IVirusTotalService
    {
        Task<string> GetFileReportAsync(string hash);
        Task<string> GetUrlReportAsync(string url);
        Task<string> GetAnalysisResultAsync(string analysisID);
        Task<string> GetIPAddressReportAsync(string ipAddress);
        Task<string> UploadFileAsync(byte[] fileBytes, string fileName);
    }
}
