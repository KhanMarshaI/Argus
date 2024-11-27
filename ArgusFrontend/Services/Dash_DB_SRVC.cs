using System.Data.SqlClient;

namespace ArgusFrontend.Services
{

    public class Dash_DB_SRVC
    {
        private readonly string _connectionString;

        public Dash_DB_SRVC()
        {
            _connectionString = "Server=DESKTOP-440RGDT;Database=argus;Trusted_Connection=True;";
        }

        public async Task<(int TotalURLs, int TotalFiles, int MaliciousURLs, int MaliciousFiles)> GetDashboardStatsAsync()
        {
            string query = @"
                SELECT 
                    (SELECT COUNT(*) FROM URLAnalysis) AS TotalURLs,
                    (SELECT COUNT(*) FROM FileReports) AS TotalFiles,
                    (SELECT COUNT(*) FROM Analysis WHERE Status = 'completed' AND Malicious > 0) AS MaliciousURLs,
                    (SELECT COUNT(*) FROM FileReports WHERE Malicious > 0) AS MaliciousFiles;
            ";

            using (var conn = new SqlConnection(_connectionString))
            {
                await conn.OpenAsync();

                using (var cmd = new SqlCommand(query, conn))
                using (var reader = await cmd.ExecuteReaderAsync())
                {
                    if (await reader.ReadAsync())
                    {
                        return (
                            reader.GetInt32(0), // Total URLs
                            reader.GetInt32(1), // Total Files
                            reader.GetInt32(2), // Malicious URLs
                            reader.GetInt32(3)  // Malicious Files
                        );
                    }
                }
            }
            return (0, 0, 0, 0);
        }

        // Fetch recent activity for URLs
        public async Task<List<(string URL, string Status, DateTime CreatedAt)>> GetRecentURLActivityAsync()
        {
            string query = @"
                SELECT 
                    U.URL, 
                    A.Status, 
                    U.CreatedAT 
                FROM URLAnalysis U
                INNER JOIN Analysis A ON U.AnalysisID = A.AnalysisID
                ORDER BY U.CreatedAT DESC
                OFFSET 0 ROWS FETCH NEXT 10 ROWS ONLY;
            ";

            var recentURLs = new List<(string URL, string Status, DateTime CreatedAt)>();

            using (var conn = new SqlConnection(_connectionString))
            {
                await conn.OpenAsync();

                using (var cmd = new SqlCommand(query, conn))
                using (var reader = await cmd.ExecuteReaderAsync())
                {
                    while (await reader.ReadAsync())
                    {
                        recentURLs.Add((
                            reader.GetString(0), // URL
                            reader.GetString(1), // Status
                            reader.GetDateTime(2) // CreatedAt
                        ));
                    }
                }
            }
            return recentURLs;
        }

        // Fetch recent activity for Files
        public async Task<List<(string FileHashSHA, string FileType, DateTime CreatedAt)>> GetRecentFileActivityAsync()
        {
            string query = @"
                SELECT 
                    FileHashSHA, 
                    FileType, 
                    CreatedAt 
                FROM FileReports
                ORDER BY CreatedAt DESC
                OFFSET 0 ROWS FETCH NEXT 10 ROWS ONLY;
            ";

            var recentFiles = new List<(string FileHashSHA, string FileType, DateTime CreatedAt)>();

            using (var conn = new SqlConnection(_connectionString))
            {
                await conn.OpenAsync();

                using (var cmd = new SqlCommand(query, conn))
                using (var reader = await cmd.ExecuteReaderAsync())
                {
                    while (await reader.ReadAsync())
                    {
                        recentFiles.Add((
                            reader.GetString(0), // FileHashSHA
                            reader.GetString(1), // FileType
                            reader.GetDateTime(2) // CreatedAt
                        ));
                    }
                }
            }
            return recentFiles;
        }
    }

}
