using System.Data.SqlClient;
using System.Text.Json;
using fileHash;
using BCrypt.Net;
using Dapper;
using ArgusFrontend.Models;
using System.Text;

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

            string query = @"
        SELECT fr.*, fs.*, si.*, ar.EngineName, ar.Category, ar.Result
        FROM FileReports fr
        LEFT JOIN FileSignatures fs ON fr.ID = fs.FileReportID
        LEFT JOIN SignatureInfo si ON fr.ID = si.FileReportID
        LEFT JOIN AnalysisResults ar ON fr.ID = ar.FileReportID
        WHERE fs." + hashType + @" = @FileHash";

            using var command = new SqlCommand(query, conn);
            command.Parameters.AddWithValue("@FileHash", filehash);

            var lastAnalysisResults = new Dictionary<string, LastAnalysisResult>();
            Hash? hash = null;

            using var reader = await command.ExecuteReaderAsync();
            while (await reader.ReadAsync())
            {
                if (hash == null)
                {
                    hash = new Hash
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
                                Names = reader["AnalyzedNames"].ToString().Split(','),
                                LastModificationDate = reader["LastModificationDate"] == DBNull.Value
                                    ? 0
                                    : (long)((DateTime)reader["LastModificationDate"])
                                        .ToUniversalTime()
                                        .Subtract(new DateTime(1970, 1, 1))
                                        .TotalSeconds,
                                SignatureInfo = new SignatureInfo
                                {
                                    Description = reader["Description"].ToString(),
                                    FileVersion = reader["FileVersion"].ToString(),
                                    OriginalName = reader["OriginalName"].ToString(),
                                    Product = reader["Product"].ToString(),
                                    InternalName = reader["InternalName"].ToString(),
                                    Copyright = reader["Copyright"].ToString()
                                }
                            }
                        }
                    };
                }

                // Populate LastAnalysisResults
                if (!reader.IsDBNull(reader.GetOrdinal("EngineName")))
                {
                    string engineName = reader["EngineName"].ToString();
                    if (!lastAnalysisResults.ContainsKey(engineName))
                    {
                        lastAnalysisResults[engineName] = new LastAnalysisResult
                        {
                            EngineName = engineName,
                            Category = reader["Category"].ToString(),
                            Result = reader["Result"].ToString()
                        };
                    }
                }
            }

            // Assign collected LastAnalysisResults to the hash object
            if (hash != null && lastAnalysisResults.Count > 0)
            {
                hash.Data.Attributes.LastAnalysisResults = lastAnalysisResults;
            }

            return hash;
        }

        public async Task StoreHashReportAsync(Hash report, string username)
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

                string setContextQuery = "SET CONTEXT_INFO @User";
                using var cmd = new SqlCommand(setContextQuery, connection);
                cmd.Parameters.Add(new SqlParameter("@User", username)
                {
                    Value = Encoding.UTF8.GetBytes(username.PadRight(128))
                });

                await cmd.ExecuteNonQueryAsync();

                using (var transaction = connection.BeginTransaction())
                {
                    try
                    {
                        string query = "INSERT INTO FileReports " +
                               "(FileHashSHA, FileID, FileType, FileExtension, Magic, Reputation, Malicious, Suspicious, " +
                               "Harmless, Undetected, AnalyzedNames, LastModificationDate) " +
                               "OUTPUT INSERTED.ID " +
                               "VALUES (@FileHash, @FileID, @FileType, @FileExtension, @Magic, @Reputation, @Malicious, " +
                               "@Suspicious, @Harmless, @Undetected, @AnalyzedNames, @LastModificationDate)";

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
                        command.Parameters.AddWithValue("@LastModificationDate", report.Data.Attributes.LastModificationDate == 0
                        ? (object)DBNull.Value
                        : DateTimeOffset.FromUnixTimeSeconds(report.Data.Attributes.LastModificationDate).UtcDateTime);

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

                        if (report.Data.Attributes.LastAnalysisResults != null)
                        {
                            foreach (var result in report.Data.Attributes.LastAnalysisResults)
                            {
                                string resultQuery = "INSERT INTO AnalysisResults " +
                                                     "(FileReportID, EngineName, Category, Result) " +
                                                     "VALUES (@FileReportID, @EngineName, @Category, @Result)";

                                using var resultCommand = new SqlCommand(resultQuery, connection, transaction);
                                resultCommand.Parameters.AddWithValue("@FileReportID", reportID);
                                resultCommand.Parameters.AddWithValue("@EngineName", result.Value.EngineName ?? (object)DBNull.Value);
                                resultCommand.Parameters.AddWithValue("@Category", result.Value.Category ?? (object)DBNull.Value);
                                resultCommand.Parameters.AddWithValue("@Result", result.Value.Result ?? (object)DBNull.Value);

                                await resultCommand.ExecuteNonQueryAsync();
                            }
                        }

                        string infoQuery = "INSERT INTO SignatureInfo VALUES(@reportId, @desc, @FileVer, @Original, @Prod, @Internal" +
                            ",@Copyright)";
                        using var infoCmd = new SqlCommand(@infoQuery, connection, transaction);
                        infoCmd.Parameters.AddWithValue("@reportId", reportID);
                        infoCmd.Parameters.AddWithValue("@desc", report.Data.Attributes.SignatureInfo.Description);
                        infoCmd.Parameters.AddWithValue("@FileVer", report.Data.Attributes.SignatureInfo.FileVersion);
                        infoCmd.Parameters.AddWithValue("@Original", report.Data.Attributes.SignatureInfo.OriginalName);
                        infoCmd.Parameters.AddWithValue("@Prod", report.Data.Attributes.SignatureInfo.Product);
                        infoCmd.Parameters.AddWithValue("@Internal", report.Data.Attributes.SignatureInfo.InternalName);
                        infoCmd.Parameters.AddWithValue("@Copyright", report.Data.Attributes.SignatureInfo.Copyright);

                        await infoCmd.ExecuteNonQueryAsync();

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

        public async Task StoreHashReportAsync(CustomFileHash report, string username)
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

                string setContextQuery = "SET CONTEXT_INFO @User";
                using var cmd = new SqlCommand(setContextQuery, connection);
                cmd.Parameters.Add(new SqlParameter("@User", username)
                {
                    Value = Encoding.UTF8.GetBytes(username.PadRight(128))
                });

                await cmd.ExecuteNonQueryAsync();

                using (var transaction = connection.BeginTransaction())
                {
                    try
                    {
                        string query = "INSERT INTO FileReports " +
                               "(FileHashSHA, FileID, FileType, FileExtension, Magic, Reputation, Malicious, Suspicious, " +
                               "Harmless, Undetected, AnalyzedNames, LastModificationDate) " +
                               "OUTPUT INSERTED.ID " +
                               "VALUES (@FileHash, @FileID, @FileType, @FileExtension, @Magic, @Reputation, @Malicious, " +
                               "@Suspicious, @Harmless, @Undetected, @AnalyzedNames, @LastModificationDate)";

                        using var command = new SqlCommand(query, connection, transaction);
                        command.Parameters.AddWithValue("@FileHash", fileHash);
                        command.Parameters.AddWithValue("@FileId", report.Id ?? (object)DBNull.Value);
                        command.Parameters.AddWithValue("@FileType", report.Type ?? (object)DBNull.Value);
                        command.Parameters.AddWithValue("@FileExtension", report.Extension ?? (object)DBNull.Value);
                        command.Parameters.AddWithValue("@Magic", report.Magic ?? (object)DBNull.Value);
                        command.Parameters.AddWithValue("@Reputation", report.Reputation);
                        command.Parameters.AddWithValue("@Malicious", report.Malicious);
                        command.Parameters.AddWithValue("@Suspicious", report.Suspicious);
                        command.Parameters.AddWithValue("@Harmless", report.Harmless);
                        command.Parameters.AddWithValue("@Undetected", report.Undetected);
                        command.Parameters.AddWithValue("@AnalyzedNames", report.Names);
                        command.Parameters.AddWithValue("@LastModificationDate", report.LastModificationDate);

                        int reportID = (int)await command.ExecuteScalarAsync();

                        string signatureQuery = "INSERT INTO FileSignatures " +
                                                "(FileReportID, MD5, SHA1, SHA256, TLSH, VHASH) " +
                                                "VALUES (@FileReportID, @MD5, @SHA1, @SHA256, @TLSH, @VHASH)";

                        using var sigCommand = new SqlCommand(signatureQuery, connection, transaction);
                        sigCommand.Parameters.AddWithValue("@FileReportId", reportID);
                        sigCommand.Parameters.AddWithValue("@MD5", report.MD5 ?? (object)DBNull.Value);
                        sigCommand.Parameters.AddWithValue("@SHA1", report.SHA1 ?? (object)DBNull.Value);
                        sigCommand.Parameters.AddWithValue("@SHA256", report.SHA256 ?? (object)DBNull.Value);
                        sigCommand.Parameters.AddWithValue("@TLSH", report.TLSH ?? (object)DBNull.Value);
                        sigCommand.Parameters.AddWithValue("@VHASH", report.VHASH ?? (object)DBNull.Value);

                        await sigCommand.ExecuteNonQueryAsync();

                        if (report.LastAnalysisResults != null)
                        {
                            foreach (var result in report.LastAnalysisResults)
                            {
                                string resultQuery = "INSERT INTO AnalysisResults " +
                                                     "(FileReportID, EngineName, Category, Result) " +
                                                     "VALUES (@FileReportID, @EngineName, @Category, @Result)";

                                using var resultCommand = new SqlCommand(resultQuery, connection, transaction);
                                resultCommand.Parameters.AddWithValue("@FileReportID", reportID);
                                resultCommand.Parameters.AddWithValue("@EngineName", result.Value.EngineName ?? (object)DBNull.Value);
                                resultCommand.Parameters.AddWithValue("@Category", result.Value.Category ?? (object)DBNull.Value);
                                resultCommand.Parameters.AddWithValue("@Result", result.Value.Result ?? (object)DBNull.Value);

                                await resultCommand.ExecuteNonQueryAsync();
                            }
                        }

                        string infoQuery = "INSERT INTO SignatureInfo VALUES(@reportId, @desc, @FileVer, @Original, @Prod, @Internal" +
                            ",@Copyright)";
                        using var infoCmd = new SqlCommand(@infoQuery, connection, transaction);
                        infoCmd.Parameters.AddWithValue("@reportId", reportID);
                        infoCmd.Parameters.AddWithValue("@desc", report.SignatureInfo.Description);
                        infoCmd.Parameters.AddWithValue("@FileVer", report.SignatureInfo.FileVersion);
                        infoCmd.Parameters.AddWithValue("@Original", report.SignatureInfo.OriginalName);
                        infoCmd.Parameters.AddWithValue("@Prod", report.SignatureInfo.Product);
                        infoCmd.Parameters.AddWithValue("@Internal", report.SignatureInfo.InternalName);
                        infoCmd.Parameters.AddWithValue("@Copyright", report.SignatureInfo.Copyright);

                        await infoCmd.ExecuteNonQueryAsync();

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

        public async Task<string> GetUserAuthLevel(string username)
        {
            using (var con = new SqlConnection(connectionString))
            {
                string query = "SELECT authLevel FROM authorized_users WHERE username = @Username";

                await con.OpenAsync();

                using (var cmd = new SqlCommand(query, con))
                {
                    cmd.Parameters.AddWithValue("@Username", username);
                    var result = await cmd.ExecuteScalarAsync();

                    // Return the result if found, otherwise return null or a default value
                    return result != null ? result.ToString() : null;
                }
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

                string query = "INSERT INTO authorized_users (username, password, created_by, comments, authLevel) " +
                               "VALUES (@username, @password, @created_by, @comments, @authLevel)";

                using (var command = new SqlCommand(query, connection))
                {
                    // Add parameters with values from registerModel
                    string hashPassword = BCrypt.Net.BCrypt.HashPassword(registerModel.password);
                    command.Parameters.AddWithValue("@username", registerModel.username);
                    command.Parameters.AddWithValue("@password", hashPassword);
                    command.Parameters.AddWithValue("@created_by", registerModel.created_by);
                    command.Parameters.AddWithValue("@comments", (object)registerModel.comments ?? DBNull.Value);
                    command.Parameters.AddWithValue("@authLevel", registerModel.authLevel);

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

        public async Task<List<Hash>> GetAllHashReportsAsync()
        {
            var hashList = new List<Hash>();

            using var conn = new SqlConnection(connectionString);
            await conn.OpenAsync();

            string query = @"
                SELECT fr.*, fs.*, si.*, ar.EngineName, ar.Category, ar.Result
                FROM FileReports fr
                LEFT JOIN FileSignatures fs ON fr.ID = fs.FileReportID
                LEFT JOIN SignatureInfo si ON fr.ID = si.FileReportID
                LEFT JOIN AnalysisResults ar ON fr.ID = ar.FileReportID";

            using var command = new 
                SqlCommand(query, conn);

            var hashDictionary = new Dictionary<string, Hash>();

            using var reader = await command.ExecuteReaderAsync();
            while (await reader.ReadAsync())
            {
                string fileHashSHA = reader["FileHashSHA"]?.ToString() ?? "N/A";

                // Check if the current hash record already exists in the dictionary
                if (!hashDictionary.ContainsKey(fileHashSHA))
                {
                    var hash = new Hash
                    {
                        Data = new Data
                        {
                            Id = fileHashSHA,
                            Type = reader["FileType"]?.ToString() ?? "N/A",
                            Attributes = new Attributes
                            {
                                TypeExtension = reader["FileExtension"]?.ToString() ?? "N/A",
                                Magic = reader["Magic"]?.ToString() ?? "N/A",
                                Reputation = reader["Reputation"] == DBNull.Value ? 0 : Convert.ToInt32(reader["Reputation"]),
                                LastAnalysisStats = new LastAnalysisStats
                                {
                                    Malicious = reader["Malicious"] == DBNull.Value ? 0 : Convert.ToInt32(reader["Malicious"]),
                                    Suspicious = reader["Suspicious"] == DBNull.Value ? 0 : Convert.ToInt32(reader["Suspicious"]),
                                    Harmless = reader["Harmless"] == DBNull.Value ? 0 : Convert.ToInt32(reader["Harmless"]),
                                    Undetected = reader["Undetected"] == DBNull.Value ? 0 : Convert.ToInt32(reader["Undetected"])
                                },
                                Md5 = reader["MD5"]?.ToString() ?? "N/A",
                                Sha1 = reader["SHA1"]?.ToString() ?? "N/A",
                                Sha256 = reader["SHA256"]?.ToString() ?? "N/A",
                                Tlsh = reader["TLSH"]?.ToString() ?? "N/A",
                                Vhash = reader["VHASH"]?.ToString() ?? "N/A",
                                Names = reader["AnalyzedNames"] == DBNull.Value ? new string[] { "N/A" } : reader["AnalyzedNames"].ToString().Split(','),
                                LastModificationDate = reader["LastModificationDate"] == DBNull.Value
                                    ? 0
                                    : (long)((DateTime)reader["LastModificationDate"])
                                        .ToUniversalTime()
                                        .Subtract(new DateTime(1970, 1, 1))
                                        .TotalSeconds,
                                SignatureInfo = new SignatureInfo
                                {
                                    Description = reader["Description"]?.ToString() ?? "N/A",
                                    FileVersion = reader["FileVersion"]?.ToString() ?? "N/A",
                                    OriginalName = reader["OriginalName"]?.ToString() ?? "N/A",
                                    Product = reader["Product"]?.ToString() ?? "N/A",
                                    InternalName = reader["InternalName"]?.ToString() ?? "N/A",
                                    Copyright = reader["Copyright"]?.ToString() ?? "N/A"
                                },
                                LastAnalysisResults = new Dictionary<string, LastAnalysisResult>()
                            }
                        }
                    };

                    hashDictionary[fileHashSHA] = hash;
                }

                // Add Analysis Results to the existing hash object
                var currentHash = hashDictionary[fileHashSHA];
                if (!reader.IsDBNull(reader.GetOrdinal("EngineName")))
                {
                    string engineName = reader["EngineName"]?.ToString() ?? "N/A";
                    if (!currentHash.Data.Attributes.LastAnalysisResults.ContainsKey(engineName))
                    {
                        currentHash.Data.Attributes.LastAnalysisResults[engineName] = new LastAnalysisResult
                        {
                            EngineName = engineName,
                            Category = reader["Category"]?.ToString() ?? "N/A",
                            Result = reader["Result"]?.ToString() ?? "N/A"
                        };
                    }
                }
            }

            // Convert dictionary values to a list
            hashList = hashDictionary.Values.ToList();
            return hashList;
        }



    }
}
