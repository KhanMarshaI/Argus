using System.Data.SqlClient;
using System.Text.Json;
using fileHash;
using BCrypt.Net;
using Dapper;

namespace ArgusFrontend.Services
{
    public class DatabaseService
    {
        private readonly string connectionString;
        private readonly string dbPass = Environment.GetEnvironmentVariable("DB_PASSWORD");

        public DatabaseService()
        {
            connectionString = "Server=MARSHAL;Database=argus;Trusted_Connection=True;";
        }

        private string DetermineHashType(string fileHash)
        {
            return fileHash.Length switch
            {
                32 => "MD5",
                40 => "SHA1",
                64 => "SHA256",
                _ => throw new ArgumentException("Invalid hash length. Please provide a valid MD5, SHA1, or SHA256 hash.")
            };
        }

        public async Task<Hash?> GetHashReportAsync(string filehash)
        {
            using var conn = new SqlConnection(connectionString);
            await conn.OpenAsync();

            // Determine the hash type (column) to query based on hash length
            string hashType = DetermineHashType(filehash);
            string query = "SELECT * FROM FileReports fr " +
                           "LEFT JOIN FileSignatures fs ON fr.ID = fs.FileReportID " +
                           $"WHERE fs.{hashType} = @FileHash";

            using var command = new SqlCommand(query, conn);
            command.Parameters.AddWithValue("@FileHash", filehash);

            using var reader = await command.ExecuteReaderAsync();
            if (await reader.ReadAsync())
            {
                return new Hash
                {
                    Data = new Data
                    {
                        Id = reader["FileHashSHA"].ToString(),
                        Type = reader["FileType"].ToString(),
                        Attributes = new Attributes
                        {
                            TypeExtension = reader["FileExtension"].ToString(),
                            Magic = reader["Magic"].ToString(),
                            Reputation = Convert.ToInt32(reader["Reputation"]),
                            LastAnalysisStats = new LastAnalysisStats
                            {
                                Malicious = Convert.ToInt32(reader["Malicious"]),
                                Suspicious = Convert.ToInt32(reader["Suspicious"]),
                                Harmless = Convert.ToInt32(reader["Harmless"]),
                                Undetected = Convert.ToInt32(reader["Undetected"])
                            },
                            Md5 = reader["MD5"].ToString(),
                            Sha1 = reader["SHA1"].ToString(),
                            Sha256 = reader["SHA256"].ToString(),
                            Tlsh = reader["TLSH"].ToString(),
                            Vhash = reader["VHASH"].ToString(),
                            Names = reader["AnalyzedNames"].ToString().Split(',')
                        }
                    }
                };
            }
            return null;
        }

        public async Task StoreHashReportAsync(Hash report)
        {
            // Determine the appropriate hash type based on the available hash value
            string? fileHash = report.Data.Attributes.Sha256 ?? report.Data.Attributes.Sha1 ?? report.Data.Attributes.Md5;
            if (fileHash == null)
            {
                throw new ArgumentException("No valid hash provided in the report.");
            }

            string hashType = DetermineHashType(fileHash);

            // Check if the hash already exists to prevent duplicates
            if (await HashExistsAsync(fileHash, hashType))
            {
                Console.WriteLine("Hash already exists in the database.");
                return;
            }

            using (var connection = new SqlConnection(connectionString))
            {
                await connection.OpenAsync();
                using (var transaction = connection.BeginTransaction())
                {
                    try
                    {
                        string query = "INSERT INTO FileReports " +
                                       "(FileHashSHA, FileID, FileType, FileExtension, Magic, Reputation, Malicious, Suspicious, " +
                                       "Harmless, Undetected, AnalyzedNames) " +
                                       "OUTPUT INSERTED.ID " +
                                       "VALUES (@FileHash, @FileID, @FileType, @FileExtension, @Magic, @Reputation, @Malicious, " +
                                       "@Suspicious, @Harmless, @Undetected, @AnalyzedNames)";

                        using var command = new SqlCommand(query, connection, transaction);
                        command.Parameters.AddWithValue("@FileHash", fileHash);
                        command.Parameters.AddWithValue("@FileId", report.Data.Id ?? (object)DBNull.Value);
                        command.Parameters.AddWithValue("@FileType", report.Data.Type ?? (object)DBNull.Value);
                        command.Parameters.AddWithValue("@FileExtension", report.Data.Attributes.TypeExtension ?? (object)DBNull.Value);
                        command.Parameters.AddWithValue("@Magic", report.Data.Attributes.Magic ?? (object)DBNull.Value);
                        command.Parameters.AddWithValue("@Reputation", report.Data.Attributes.Reputation);
                        command.Parameters.AddWithValue("@Malicious", report.Data.Attributes.LastAnalysisStats.Malicious);
                        command.Parameters.AddWithValue("@Suspicious", report.Data.Attributes.LastAnalysisStats.Suspicious);
                        command.Parameters.AddWithValue("@Harmless", report.Data.Attributes.LastAnalysisStats.Harmless);
                        command.Parameters.AddWithValue("@Undetected", report.Data.Attributes.LastAnalysisStats.Undetected);
                        command.Parameters.AddWithValue("@AnalyzedNames",
                            string.Join(", ", report.Data.Attributes.Names ?? Array.Empty<string>()));

                        int reportID = (int)await command.ExecuteScalarAsync();

                        string signatureQuery = "INSERT INTO FileSignatures " +
                                                "(FileReportID, MD5, SHA1, SHA256, TLSH, VHASH) " +
                                                "VALUES (@FileReportID, @MD5, @SHA1, @SHA256, @TLSH, @VHASH)";

                        using var sigCommand = new SqlCommand(signatureQuery, connection, transaction);
                        sigCommand.Parameters.AddWithValue("@FileReportId", reportID);
                        sigCommand.Parameters.AddWithValue("@MD5", report.Data.Attributes.Md5 ?? (object)DBNull.Value);
                        sigCommand.Parameters.AddWithValue("@SHA1", report.Data.Attributes.Sha1 ?? (object)DBNull.Value);
                        sigCommand.Parameters.AddWithValue("@SHA256", report.Data.Attributes.Sha256 ?? (object)DBNull.Value);
                        sigCommand.Parameters.AddWithValue("@TLSH", report.Data.Attributes.Tlsh ?? (object)DBNull.Value);
                        sigCommand.Parameters.AddWithValue("@VHASH", report.Data.Attributes.Vhash ?? (object)DBNull.Value);

                        await sigCommand.ExecuteNonQueryAsync();
                        transaction.Commit();
                    }

                    catch (Exception ex)
                    {
                        transaction.Rollback();
                        Console.WriteLine($"Error storing data: {ex.Message}");
                    }
                    
                }
            }
        }

        public async Task<bool> HashExistsAsync(string fileHash, string hashType)
        {
            string query = hashType switch
            {
                "SHA256" => "SELECT 1 FROM FileReports WHERE FileHashSHA = @FileHash",
                "SHA1" => "SELECT 1 FROM FileSignatures WHERE SHA1 = @FileHash",
                "MD5" => "SELECT 1 FROM FileSignatures WHERE MD5 = @FileHash",
                _ => throw new ArgumentException("Invalid hash type")
            };

            using var connection = new SqlConnection(connectionString);
            await connection.OpenAsync();
            using var command = new SqlCommand(query, connection);
            command.Parameters.AddWithValue("@FileHash", fileHash);
            return await command.ExecuteScalarAsync() != null;
        }


        //Authorization
        public async Task<bool> AuthorizeUserAsync(string username, string password)
        {
            using (var connection = new SqlConnection(connectionString))
            {
                string query = "SELECT password FROM authorized_users WHERE username = @Username";
                var storedHash = await connection.QuerySingleOrDefaultAsync<string>(query, new { @Username = username });

                if(storedHash == null)
                {
                    return false;
                }

                return BCrypt.Net.BCrypt.Verify(password, storedHash);
            }
        }
    }
}
