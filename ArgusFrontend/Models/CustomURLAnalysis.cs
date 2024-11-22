using System.ComponentModel.DataAnnotations;

namespace ArgusFrontend.Models
{
    public class CustomURLAnalysis
    {
        [Required(AllowEmptyStrings = false, ErrorMessage = "Provide URL Analysis ID.")]
        public string Id { get; set; }

        [Required(AllowEmptyStrings = false, ErrorMessage = "Provide Type.")]
        public string Type { get; set; }

        [Required(AllowEmptyStrings = false, ErrorMessage = "Provide URL.")]
        public string URL { get; set; }

        [Required(AllowEmptyStrings = false, ErrorMessage = "Provide Analysis Status.")]
        [RegularExpression(@"^(queued|completed)$", ErrorMessage = "Status must be either 'queued' or 'completed'")]
        public string Status { get; set; }

        [Required]
        public int Malicious { get; set; }
        [Required]
        public int Harmless { get; set; }
        [Required]
        public int Suspicious { get; set; }
        [Required]
        public int Undetected { get; set; }
    }
}