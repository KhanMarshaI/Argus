using System.Data.SqlClient;
using System.Text.Json;
using URLAnalysis;
using _Analysis;
using ArgusFrontend.Models;
using System.Data;
using System.Text;
using System;


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

        public async Task<URLRep> GetURLReportAsync(string URL)
        {
            using var con = new SqlConnection(connectionString);
            await con.OpenAsync();

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

        public async Task<Analysis> GetAnalysisAsync(string ID)
        {
            using var con = new SqlConnection(connectionString);
            await con.OpenAsync();

            string query = "SELECT * FROM Analysis WHERE AnalysisID = @ID";

            using var command = new SqlCommand(query, con);
            command.Parameters.AddWithValue("@ID", ID);
            using var reader = await command.ExecuteReaderAsync();
            if (await reader.ReadAsync())
            {
                return new Analysis
                {
                    Data = new AnalysisData
                    {
                        Id = reader["AnalysisID"].ToString(),
                        Type = reader["Type"].ToString(),
                        Attributes = new Attributes
                        {
                            Status = reader["Status"].ToString(),
                            Stats = new Stats
                            {
                                Malicious = Convert.ToInt32(reader["Malicious"]),
                                Harmless = Convert.ToInt32(reader["Harmless"]),
                                Suspicious = Convert.ToInt32(reader["Suspicious"]),
                                Undetected = Convert.ToInt32(reader["Undetected"])

                            }
                        }
                    }

                };
            }
            return null;
        }

        public async Task StoreURLReportAsync(URLRep url, Analysis analysis, string username)
        {
            using var conn = new SqlConnection(connectionString);
            await conn.OpenAsync();

            string setContextQuery = "SET CONTEXT_INFO @User";
            using var command = new SqlCommand(setContextQuery, conn);
            command.Parameters.Add(new SqlParameter("@User", SqlDbType.VarBinary)
            {
                Value = Encoding.UTF8.GetBytes(username.PadRight(128)) // Ensure exactly 128 bytes
            });

            await command.ExecuteNonQueryAsync();

            string existingStatusQuery = "SELECT Status FROM Analysis WHERE AnalysisID = @anid";
            using var checkCmd = new SqlCommand(existingStatusQuery, conn);
            checkCmd.Parameters.AddWithValue("@anid", url.Data.Id);
            var existingStatus = await checkCmd.ExecuteScalarAsync() as string;

            using (var transaction = conn.BeginTransaction())
            {
                try
                {
                    if (existingStatus != null)
                    {
                        if (existingStatus.Equals("queued", StringComparison.OrdinalIgnoreCase) &&
                            analysis.Data.Attributes.Status.Equals("completed", StringComparison.OrdinalIgnoreCase))
                        {
                            string updateQuery = @"
                        UPDATE Analysis 
                        SET Status = @Status, 
                            Malicious = @Malicious, 
                            Suspicious = @Suspicious, 
                            Undetected = @Undetected, 
                            Harmless = @Harmless 
                        WHERE AnalysisID = @AnID";

                            using var updateCmd = new SqlCommand(updateQuery, conn, transaction);
                            updateCmd.Parameters.AddWithValue("@Status", analysis.Data.Attributes.Status ?? (object)DBNull.Value);
                            updateCmd.Parameters.AddWithValue("@Malicious", analysis.Data.Attributes.Stats.Malicious);
                            updateCmd.Parameters.AddWithValue("@Suspicious", analysis.Data.Attributes.Stats.Suspicious);
                            updateCmd.Parameters.AddWithValue("@Undetected", analysis.Data.Attributes.Stats.Undetected);
                            updateCmd.Parameters.AddWithValue("@Harmless", analysis.Data.Attributes.Stats.Harmless);
                            updateCmd.Parameters.AddWithValue("@AnID", url.Data.Id);

                            await updateCmd.ExecuteNonQueryAsync();
                            Console.WriteLine("Updated existing 'queued' entry to 'completed'.");
                        }
                        else
                        {
                            Console.WriteLine("URL already exists with no updates required.");
                        }
                    }
                    else
                    {
                        string query = "INSERT INTO Analysis VALUES (@AnID, @Type, @Status, @Malicious, @Suspicious, @Undetected, @Harmless)";
                        using var cmd = new SqlCommand(query, conn, transaction);
                        cmd.Parameters.AddWithValue("@AnID", url.Data.Id);
                        cmd.Parameters.AddWithValue("@Type", url.Data.Type ?? (object)DBNull.Value);
                        cmd.Parameters.AddWithValue("@Status", analysis.Data.Attributes.Status ?? (object)DBNull.Value);
                        cmd.Parameters.AddWithValue("@Malicious", analysis.Data.Attributes.Stats.Malicious);
                        cmd.Parameters.AddWithValue("@Suspicious", analysis.Data.Attributes.Stats.Suspicious);
                        cmd.Parameters.AddWithValue("@Undetected", analysis.Data.Attributes.Stats.Undetected);
                        cmd.Parameters.AddWithValue("@Harmless", analysis.Data.Attributes.Stats.Harmless);

                        await cmd.ExecuteNonQueryAsync();

                        string urlQuery = "INSERT INTO URLAnalysis(URL, AnalysisID) VALUES(@URL, @AnalysisID)";
                        using var cmdURL = new SqlCommand(urlQuery, conn, transaction);
                        cmdURL.Parameters.AddWithValue("@URL", analysis.Meta.UrlInfo.Url.ToString());
                        cmdURL.Parameters.AddWithValue("@AnalysisID", url.Data.Id);

                        await cmdURL.ExecuteNonQueryAsync();

                        Console.WriteLine("Inserted new URL and analysis data successfully.");
                    }

                    transaction.Commit();
                }
                catch (Exception ex)
                {
                    transaction.Rollback();
                    Console.WriteLine($"Exception on storing URL: {ex.Message}");
                }
            }
        }

        public async Task<string> StoreURLReportAsync(CustomURLAnalysis analysis, string username)
        {
            using var conn = new SqlConnection(connectionString);
            await conn.OpenAsync();

            string setContextQuery = "SET CONTEXT_INFO @User";
            using var command = new SqlCommand(setContextQuery, conn);
            byte[] userBytes = Encoding.UTF8.GetBytes(username.PadRight(128).Substring(0, 128));
            command.Parameters.Add("@User", SqlDbType.VarBinary, 128).Value = userBytes;

            await command.ExecuteNonQueryAsync();

            string existingStatusQuery = "SELECT Status FROM Analysis WHERE AnalysisID = @anid";
            using var checkCmd = new SqlCommand(existingStatusQuery, conn);
            checkCmd.Parameters.AddWithValue("@anid", analysis.Id);
            var existingStatus = await checkCmd.ExecuteScalarAsync() as string;

            using (var transaction = conn.BeginTransaction())
            {
                try
                {
                    if (existingStatus != null)
                    {
                        if (existingStatus.Equals("queued", StringComparison.OrdinalIgnoreCase) &&
                            analysis.Status.Equals("completed", StringComparison.OrdinalIgnoreCase))
                        {
                            string updateQuery = @"
                UPDATE Analysis 
                SET Status = @Status, 
                    Malicious = @Malicious, 
                    Suspicious = @Suspicious, 
                    Undetected = @Undetected, 
                    Harmless = @Harmless 
                WHERE AnalysisID = @AnID";

                            using var updateCmd = new SqlCommand(updateQuery, conn, transaction);
                            updateCmd.Parameters.AddWithValue("@Status", analysis.Status ?? (object)DBNull.Value);
                            updateCmd.Parameters.AddWithValue("@Malicious", analysis.Malicious);
                            updateCmd.Parameters.AddWithValue("@Suspicious", analysis.Suspicious);
                            updateCmd.Parameters.AddWithValue("@Undetected", analysis.Undetected);
                            updateCmd.Parameters.AddWithValue("@Harmless", analysis.Harmless);
                            updateCmd.Parameters.AddWithValue("@AnID", analysis.Id);

                            await updateCmd.ExecuteNonQueryAsync();
                            transaction.Commit();
                            return "Updated";
                        }
                        else
                        {
                            transaction.Rollback();
                            return "NoUpdateRequired";
                        }
                    }
                    else
                    {
                        string query = "INSERT INTO Analysis VALUES (@AnID, @Type, @Status, @Malicious, @Suspicious, @Undetected, @Harmless)";
                        using var cmd = new SqlCommand(query, conn, transaction);
                        cmd.Parameters.AddWithValue("@AnID", analysis.Id);
                        cmd.Parameters.AddWithValue("@Type", analysis.Type ?? (object)DBNull.Value);
                        cmd.Parameters.AddWithValue("@Status", analysis.Status ?? (object)DBNull.Value);
                        cmd.Parameters.AddWithValue("@Malicious", analysis.Malicious);
                        cmd.Parameters.AddWithValue("@Suspicious", analysis.Suspicious);
                        cmd.Parameters.AddWithValue("@Undetected", analysis.Undetected);
                        cmd.Parameters.AddWithValue("@Harmless", analysis.Harmless);

                        await cmd.ExecuteNonQueryAsync();

                        string urlQuery = "INSERT INTO URLAnalysis(URL, AnalysisID) VALUES(@URL, @AnalysisID)";
                        using var cmdURL = new SqlCommand(urlQuery, conn, transaction);
                        cmdURL.Parameters.AddWithValue("@URL", analysis.URL.ToString());
                        cmdURL.Parameters.AddWithValue("@AnalysisID", analysis.Id);

                        await cmdURL.ExecuteNonQueryAsync();
                        transaction.Commit();
                        return "Inserted"; 
                    }
                }
                catch (Exception ex)
                {
                    transaction.Rollback();
                    Console.WriteLine($"Exception on storing URL: {ex.Message}");
                    return "Error";
                }
            }
        }


        public async Task<bool> UrlExistsAsync(string anID)
        {
            string query = "SELECT 1 FROM Analysis WHERE AnalysisID = @anid";
            using var conn = new SqlConnection(connectionString);
            await conn.OpenAsync();

            using var cmd = new SqlCommand(query, conn);
            cmd.Parameters.AddWithValue("@anid", anID);
            return await cmd.ExecuteScalarAsync() != null;
        }

        public async Task<List<Analysis>> GetAllAnalysesAsync()
        {
            var analysisList = new List<Analysis>();

            using var con = new SqlConnection(connectionString);
            await con.OpenAsync();

            string query = @"
                SELECT a.AnalysisID, a.Type, a.Status, a.Malicious, a.Harmless, a.Suspicious, a.Undetected, 
                       u.URL
                FROM Analysis a
                LEFT JOIN URLAnalysis u ON a.AnalysisID = u.AnalysisID
            ";

            using var command = new SqlCommand(query, con);
            using var reader = await command.ExecuteReaderAsync();

            while (await reader.ReadAsync())
            {
                var analysis = new Analysis
                {
                    Data = new AnalysisData
                    {
                        Id = reader["AnalysisID"]?.ToString() ?? "N/A",
                        Type = reader["Type"]?.ToString() ?? "N/A",
                        Attributes = new Attributes
                        {
                            Status = reader["Status"]?.ToString() ?? "N/A",
                            Stats = new Stats
                            {
                                Malicious = reader["Malicious"] == DBNull.Value ? 0 : Convert.ToInt32(reader["Malicious"]),
                                Harmless = reader["Harmless"] == DBNull.Value ? 0 : Convert.ToInt32(reader["Harmless"]),
                                Suspicious = reader["Suspicious"] == DBNull.Value ? 0 : Convert.ToInt32(reader["Suspicious"]),
                                Undetected = reader["Undetected"] == DBNull.Value ? 0 : Convert.ToInt32(reader["Undetected"])
                            }
                        }
                    },
                    Meta = new Meta
                    {
                        UrlInfo = new UrlInfo
                        {
                            Url = reader["URL"] != DBNull.Value
                            ? (Uri.TryCreate(reader["URL"].ToString(), UriKind.Absolute, out var uri) ? uri : null)
                            : null
                        }
                    }
                };

                // Add the analysis object to the list
                analysisList.Add(analysis);
            }

            return analysisList;
        }


    }
}
