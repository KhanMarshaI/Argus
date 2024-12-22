using System.Data.SqlClient;
using System.Data;
using System.Text;

namespace ArgusFrontend.Services
{
    public class LoggingService
    {
        private readonly string _connectionString;

        public LoggingService()
        {
            _connectionString = "Server=MARSHAL;Database=argus;Trusted_Connection=True;";
        }

        public async Task<List<LogEntry>> GetURLLogging()
        {
            var logs = new List<LogEntry>();
            using var connection = new SqlConnection(_connectionString);
            using var command = new SqlCommand("GetURLLogging", connection)
            {
                CommandType = CommandType.StoredProcedure
            };

            await connection.OpenAsync();
            using var reader = await command.ExecuteReaderAsync();
            while (await reader.ReadAsync())
            {
                logs.Add(new LogEntry
                {
                    LogID = reader.GetInt32(0),
                    ReferenceID = reader.GetString(1), // AnalysisID
                    Action = reader.GetString(2),
                    User = reader.GetString(3),
                    Time = reader.GetDateTime(4)
                });
            }
            return logs;
        }

        public async Task<List<LogEntry>> GetFileScanLogging()
        {
            var logs = new List<LogEntry>();
            using var connection = new SqlConnection(_connectionString);
            using var command = new SqlCommand("GetFileScanLogging", connection)
            {
                CommandType = CommandType.StoredProcedure
            };

            await connection.OpenAsync();
            using var reader = await command.ExecuteReaderAsync();
            while (await reader.ReadAsync())
            {
                logs.Add(new LogEntry
                {
                    LogID = reader.GetInt32(0),
                    ReferenceID = reader.GetString(1), // FileID
                    Action = reader.GetString(2),
                    User = reader.GetString(3),
                    Time = reader.GetDateTime(4)
                });
            }
            return logs;
        }

        public class LogEntry
        {
            public int LogID { get; set; }
            public string Action { get; set; }
            public string User { get; set; }
            public DateTime Time { get; set; }
            public string ReferenceID { get; set; }
        }
    }
}
