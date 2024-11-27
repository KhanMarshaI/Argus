using System.Data.SqlClient;
using System.Text.Json;
using fileHash;
using BCrypt.Net;
using Dapper;
using ArgusFrontend.Models;

namespace ArgusFrontend.Services
{
    public class DatabaseService
    {
        private readonly string connectionString;
        private readonly string dbPass = Environment.GetEnvironmentVariable("DB_PASSWORD");

        public DatabaseService()
        {
            connectionString = "Server=DESKTOP-440RGDT;Database=argus;Trusted_Connection=True;";
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
            string? fileHash;
            try
            {
                fileHash = report.Data.Attributes.Sha256 ?? report.Data.Attributes.Sha1 ?? report.Data.Attributes.Md5;

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
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error storing file hash report: {ex.Message}");
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
                        Console.WriteLine($"Error storing HASH: {ex.Message}");
                    }
                    
                }
            }
        }

        public async Task StoreHashReportAsync(CustomFileHash report)
        {
            // Validate the file hash (this validation could also happen at the UI level or before calling this method)
            if (string.IsNullOrEmpty(report.SHA256) && string.IsNullOrEmpty(report.SHA1) && string.IsNullOrEmpty(report.MD5))
            {
                throw new ArgumentException("No valid hash provided in the report.");
            }

            // Determine the primary hash type to use
            string fileHash = report.SHA256 ?? report.SHA1 ?? report.MD5;
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
                        // Insert into FileReports table
                        string query = "INSERT INTO FileReports " +
                                       "(FileHashSHA, FileID, FileType, FileExtension, Magic, Reputation, Malicious, Suspicious, " +
                                       "Harmless, Undetected, AnalyzedNames) " +
                                       "OUTPUT INSERTED.ID " +
                                       "VALUES (@FileHash, @FileID, @FileType, @FileExtension, @Magic, @Reputation, @Malicious, " +
                                       "@Suspicious, @Harmless, @Undetected, @AnalyzedNames)";

                        using var command = new SqlCommand(query, connection, transaction);
                        command.Parameters.AddWithValue("@FileHash", fileHash);
                        command.Parameters.AddWithValue("@FileID", report.Id);
                        command.Parameters.AddWithValue("@FileType", report.Type);
                        command.Parameters.AddWithValue("@FileExtension", report.Extension);
                        command.Parameters.AddWithValue("@Magic", report.Magic);
                        command.Parameters.AddWithValue("@Reputation", report.Reputation);
                        command.Parameters.AddWithValue("@Malicious", report.Malicious);
                        command.Parameters.AddWithValue("@Suspicious", report.Suspicious);
                        command.Parameters.AddWithValue("@Harmless", report.Harmless);
                        command.Parameters.AddWithValue("@Undetected", report.Undetected);
                        command.Parameters.AddWithValue("@AnalyzedNames", report.Names);

                        int reportID = (int)await command.ExecuteScalarAsync();

                        // Insert into FileSignatures table
                        string signatureQuery = "INSERT INTO FileSignatures " +
                                                "(FileReportID, MD5, SHA1, SHA256, TLSH, VHASH) " +
                                                "VALUES (@FileReportID, @MD5, @SHA1, @SHA256, @TLSH, @VHASH)";

                        using var sigCommand = new SqlCommand(signatureQuery, connection, transaction);
                        sigCommand.Parameters.AddWithValue("@FileReportID", reportID);
                        sigCommand.Parameters.AddWithValue("@MD5", report.MD5);
                        sigCommand.Parameters.AddWithValue("@SHA1", report.SHA1);
                        sigCommand.Parameters.AddWithValue("@SHA256", report.SHA256);
                        sigCommand.Parameters.AddWithValue("@TLSH", report.TLSH);
                        sigCommand.Parameters.AddWithValue("@VHASH", report.VHASH);

                        await sigCommand.ExecuteNonQueryAsync();
                        transaction.Commit();
                    }
                    catch (Exception ex)
                    {
                        transaction.Rollback();
                        Console.WriteLine($"Error storing Custom hash: {ex.Message}");
                        throw;
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

        public async Task<bool> UpdatePassword(string username, string password)
        {
            using (var connection = new SqlConnection(connectionString))
            {
                await connection.OpenAsync();
                try
                {
                    string query = "UPDATE authorized_users SET password = @password WHERE username = @username";
                    using (var command = new SqlCommand(query, connection))
                    {
                        command.Parameters.AddWithValue("@username", username);
                        string hashedPass = BCrypt.Net.BCrypt.HashPassword(password);
                        command.Parameters.AddWithValue("@password", hashedPass);

                        await command.ExecuteNonQueryAsync();
                    }
                    return true;
                }
                catch (Exception ex) { 
                    Console.WriteLine($"Updating profile didn't work: {ex.Message}");
                }
                return false;
            }
        }

        public async Task<bool> ValidateUserExists(string username)
        {
            using(var connection = new SqlConnection(connectionString))
            {
                await connection.OpenAsync();
                string query = "SELECT 1 FROM authorized_users WHERE username = @username";
                using(var command = new SqlCommand(query, connection))
                {
                    command.Parameters.AddWithValue("@username", username);
                    return await command.ExecuteScalarAsync() != null;
                }
            }
        }

        public async Task<bool> RegisterUser(RegisterModel registerModel)
        {
            using (var connection = new SqlConnection(connectionString))
            {
                await connection.OpenAsync();

                // Check if the user already exists
                if (await ValidateUserExists(registerModel.username))
                {
                    Console.WriteLine("User already exists.");
                    return false;
                }

                string query = "INSERT INTO authorized_users (username, password, created_by, comments) " +
                               "VALUES (@username, @password, @created_by, @comments)";

                using (var command = new SqlCommand(query, connection))
                {
                    // Add parameters with values from registerModel
                    string hashPassword = BCrypt.Net.BCrypt.HashPassword(registerModel.password);
                    command.Parameters.AddWithValue("@username", registerModel.username);
                    command.Parameters.AddWithValue("@password", hashPassword);
                    command.Parameters.AddWithValue("@created_by", registerModel.created_by);
                    command.Parameters.AddWithValue("@comments", (object)registerModel.comments ?? DBNull.Value);

                    try
                    {
                        await command.ExecuteNonQueryAsync();
                        return true; 
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Error registering user: {ex.Message}");
                        return false;
                    }
                }
            }
        }


    }
}
