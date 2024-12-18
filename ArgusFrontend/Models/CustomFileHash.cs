using fileHash;
using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace ArgusFrontend.Models
{
    public class CustomFileHash
    {
        [RegularExpression(@"^(.{32}|.{40}|.{64})$", ErrorMessage = "Invalid File Hash.")]
        [Required(AllowEmptyStrings = false, ErrorMessage = "Provide File Hash.")]
        public string Id { get; set; }
        [Required(AllowEmptyStrings = false, ErrorMessage = "Provide File Type.")]
        public string Type { get; set; }
        [Required(AllowEmptyStrings = false, ErrorMessage = "Provide File Extension.")]
        public string Extension { get; set; }
        [Required(AllowEmptyStrings = false, ErrorMessage = "Provide File Magic.")]
        public string Magic { get; set; }

        [Required]
        public int Reputation { get; set; }
        [Required]
        public int Malicious { get; set; }
        [Required]
        public int Harmless { get; set; }
        [Required]
        public int Suspicious { get; set; }
        [Required]
        public int Undetected { get; set; }

        [Required(AllowEmptyStrings = false, ErrorMessage = "Provide File Known Names.")]
        public string Names { get; set; }

        [Required(AllowEmptyStrings = false, ErrorMessage = "Provide MD5 Hash.")]
        public string MD5 { get; set; }
        [Required(AllowEmptyStrings = false, ErrorMessage = "Provide SHA1 Hash.")]
        public string SHA1 { get; set; }
        [Required(AllowEmptyStrings = false, ErrorMessage = "Provide SHA256 Hash.")]
        public string SHA256 { get; set; }

        public string TLSH { get; set; }

        public string VHASH { get; set; }

        public Dictionary<string, AnalysisResult> LastAnalysisResults { get; set; }

        public SignatureInfo SignatureInfo { get; set; } = new SignatureInfo();

        public DateTime? LastModificationDate { get; set; }

        public DateTime? CreatedAT { get; set; }
    }

    public partial class AnalysisResult
    {
        [JsonPropertyName("method")]
        public string Method { get; set; }

        [JsonPropertyName("engine_name")]
        public string EngineName { get; set; }

        [JsonPropertyName("engine_version")]
        public string EngineVersion { get; set; }

        [JsonPropertyName("engine_update")]
        [JsonConverter(typeof(ParseStringConverter))]
        public long EngineUpdate { get; set; }

        [JsonPropertyName("category")]
        public string Category { get; set; }

        [JsonPropertyName("result")]
        public string Result { get; set; }
    }
}
