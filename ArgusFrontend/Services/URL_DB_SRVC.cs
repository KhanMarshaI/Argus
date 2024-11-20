using System.Data.SqlClient;
using System.Text.Json;
using URLAnalysis;

namespace ArgusFrontend.Services
{
    public class URL_DB_SRVC
    {
        private readonly string connectionString;
        private readonly string dbPass = Environment.GetEnvironmentVariable("DB_PASSWORD");

        public URL_DB_SRVC()
        {
            connectionString = "Server=MARSHAL;Database=argus;Trusted_Connection=True;"; 
        }

        public async Task<URLRep?> GetURLReportAsync(string URL)
        {
            using var con = new SqlConnection(connectionString);
            con.OpenAsync();

            string query = "SELECT * FROM URLAnalysis u JOIN Analysis a ON u.AnalysisID = a.AnalysisID WHERE u.URL = @URL";

            using var command = new SqlCommand(query, con);
            command.Parameters.AddWithValue("@URL", URL);
            using var reader = await command.ExecuteReaderAsync();
            if (await reader.ReadAsync())
            {
                return new URLRep
                {
                    Data = new Data
                    {
                        Id = reader["AnalysisID"].ToString(),
                        Type = reader["Type"].ToString()
                    }
                };
            }
            return null;
        }

        public async Task<URLRep?> StoreURLReportAsync(string URL)
        {
            using var con = new SqlConnection(connectionString);
            con.OpenAsync();

            string query = "SELECT * FROM URLAnalysis u JOIN Analysis a ON u.AnalysisID = a.AnalysisID WHERE u.URL = @URL";

            using var command = new SqlCommand(query, con);
            command.Parameters.AddWithValue("@URL", URL);
            using var reader = await command.ExecuteReaderAsync();
            if (await reader.ReadAsync())
            {
                return new URLRep
                {
                    Data = new Data
                    {
                        Id = reader["AnalysisID"].ToString(),
                        Type = reader["Type"].ToString()
                    }
                };
            }
            return null;
        }

    }
}
