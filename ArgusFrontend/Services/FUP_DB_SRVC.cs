using FileAnalysis;
using System.Data.SqlClient;

namespace ArgusFrontend.Services
{
    public class FUP_DB_SRVC
    {
        private readonly string connectionString;
        
        public FUP_DB_SRVC()
        {
            connectionString = "Server=MARSHAL;Database=argus;Trusted_Connection=True;";
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

        public async Task StoreHashReportAsync(FileUploadAnalysis report, Stream? fileStream = null, long? fileSize = null)
        {
            string? fileHash;
            try
            {
                fileHash = report.Meta?.FileInfo?.Sha256 ?? report.Meta?.FileInfo?.Sha1 ?? report.Meta?.FileInfo?.Md5;

                if (fileHash == null)
                {
                    throw new ArgumentException("No valid hash provided in the report.");
                }

                string hashType = DetermineHashType(fileHash);

                // Check report status
                string reportStatus = report.Data.Attributes.Status?.ToLower() ?? "unknown";
                if (reportStatus == "queued")
                {
                    Console.WriteLine("Report is queued for scanning. No action taken.");
                    return;
                }

                // Check if the hash already exists
                if (await HashExistsAsync(fileHash, hashType))
                {
                    // If the hash exists and the status is "completed", update the existing data
                    if (reportStatus == "completed")
                    {
                        await UpdateHashReportAsync(fileHash, report, fileStream, fileSize);
                    }
                    else
                    {
                        Console.WriteLine("Hash already exists in the database with non-completed status. No action taken.");
                    }
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
                               "Harmless, Undetected, AnalyzedNames, LastModificationDate) " +
                               "OUTPUT INSERTED.ID " +
                               "VALUES (@FileHash, @FileID, NULL, NULL, NULL, NULL, @Malicious, " +
                               "@Suspicious, @Harmless, @Undetected, NULL, NULL)";

                        using var command = new SqlCommand(query, connection, transaction);
                        command.Parameters.AddWithValue("@FileHash", fileHash);
                        command.Parameters.AddWithValue("@FileId", report.Meta.FileInfo.Sha256 ?? (object)DBNull.Value);
                        command.Parameters.AddWithValue("@Malicious", report.Data.Attributes.Stats.Malicious);
                        command.Parameters.AddWithValue("@Suspicious", report.Data.Attributes.Stats.Suspicious);
                        command.Parameters.AddWithValue("@Harmless", report.Data.Attributes.Stats.Harmless);
                        command.Parameters.AddWithValue("@Undetected", report.Data.Attributes.Stats.Undetected);

                        int reportID = (int)await command.ExecuteScalarAsync();

                        string signatureQuery = "INSERT INTO FileSignatures " +
                                                "(FileReportID, MD5, SHA1, SHA256, TLSH, VHASH) " +
                                                "VALUES (@FileReportID, @MD5, @SHA1, @SHA256, NULL, NULL)";

                        using var sigCommand = new SqlCommand(signatureQuery, connection, transaction);
                        sigCommand.Parameters.AddWithValue("@FileReportId", reportID);
                        sigCommand.Parameters.AddWithValue("@MD5", report.Meta.FileInfo.Md5 ?? (object)DBNull.Value);
                        sigCommand.Parameters.AddWithValue("@SHA1", report.Meta.FileInfo.Sha1 ?? (object)DBNull.Value);
                        sigCommand.Parameters.AddWithValue("@SHA256", report.Meta.FileInfo.Sha256 ?? (object)DBNull.Value);

                        await sigCommand.ExecuteNonQueryAsync();

                        if (report.Data.Attributes.Results != null)
                        {
                            foreach (var result in report.Data.Attributes.Results)
                            {
                                string resultQuery = "INSERT INTO AnalysisResults " +
                                                     "(FileReportID, EngineName, Category, Result) " +
                                                     "VALUES (@FileReportID, @EngineName, @Category, @Result)";

                                using var resultCommand = new SqlCommand(resultQuery, connection, transaction);
                                resultCommand.Parameters.AddWithValue("@FileReportID", reportID);
                                resultCommand.Parameters.AddWithValue("@EngineName", result.Value.EngineName ?? (object)DBNull.Value);
                                resultCommand.Parameters.AddWithValue("@Category", result.Value.Category ?? (object)DBNull.Value);
                                resultCommand.Parameters.AddWithValue("@Result", result.Value.ResultResult ?? (object)DBNull.Value);

                                await resultCommand.ExecuteNonQueryAsync();
                            }
                        }

                        if (fileStream != null && fileSize != null)
                        {
                            byte[] fileBytes;
                            using (var memoryStream = new MemoryStream())
                            {
                                await fileStream.CopyToAsync(memoryStream);
                                fileBytes = memoryStream.ToArray();
                            }

                            string fileDataQuery = @"INSERT INTO FileData 
                                     (FileReportID, FileContent, FileSize, CreatedAt) 
                                     VALUES (@FileReportID, @FileContent, @FileSize, GETDATE())";

                            using var fileDataCommand = new SqlCommand(fileDataQuery, connection, transaction);
                            fileDataCommand.Parameters.AddWithValue("@FileReportID", reportID);
                            fileDataCommand.Parameters.AddWithValue("@FileContent", fileBytes);
                            fileDataCommand.Parameters.AddWithValue("@FileSize", fileSize);

                            await fileDataCommand.ExecuteNonQueryAsync();
                        }

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

        private async Task UpdateHashReportAsync(string fileHash, FileUploadAnalysis report, Stream? fileStream, long? fileSize)
        {
            using (var connection = new SqlConnection(connectionString))
            {
                await connection.OpenAsync();
                using (var transaction = connection.BeginTransaction())
                {
                    try
                    {
                        string updateQuery = @"UPDATE FileReports
                                       SET Malicious = @Malicious,
                                           Suspicious = @Suspicious,
                                           Harmless = @Harmless,
                                           Undetected = @Undetected
                                       WHERE FileHashSHA = @FileHash";

                        using var updateCommand = new SqlCommand(updateQuery, connection, transaction);
                        updateCommand.Parameters.AddWithValue("@FileHash", fileHash);
                        updateCommand.Parameters.AddWithValue("@Malicious", report.Data.Attributes.Stats.Malicious);
                        updateCommand.Parameters.AddWithValue("@Suspicious", report.Data.Attributes.Stats.Suspicious);
                        updateCommand.Parameters.AddWithValue("@Harmless", report.Data.Attributes.Stats.Harmless);
                        updateCommand.Parameters.AddWithValue("@Undetected", report.Data.Attributes.Stats.Undetected);

                        await updateCommand.ExecuteNonQueryAsync();

                        if (fileStream != null && fileSize != null)
                        {
                            byte[] fileBytes;
                            using (var memoryStream = new MemoryStream())
                            {
                                await fileStream.CopyToAsync(memoryStream);
                                fileBytes = memoryStream.ToArray();
                            }

                            string updateFileDataQuery = @"UPDATE FileData
                                                   SET FileContent = @FileContent, 
                                                       FileSize = @FileSize, 
                                                       CreatedAt = GETDATE()
                                                   WHERE FileReportID = (SELECT ID FROM FileReports WHERE FileHashSHA = @FileHash)";

                            using var fileDataCommand = new SqlCommand(updateFileDataQuery, connection, transaction);
                            fileDataCommand.Parameters.AddWithValue("@FileContent", fileBytes);
                            fileDataCommand.Parameters.AddWithValue("@FileSize", fileSize);
                            fileDataCommand.Parameters.AddWithValue("@FileHash", fileHash);

                            await fileDataCommand.ExecuteNonQueryAsync();
                        }

                        transaction.Commit();
                    }
                    catch (Exception ex)
                    {
                        transaction.Rollback();
                        Console.WriteLine($"Error updating hash report: {ex.Message}");
                    }
                }
            }

        }

    }
}
