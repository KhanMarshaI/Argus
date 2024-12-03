using System.ComponentModel.DataAnnotations;

namespace ArgusFrontend.Models
{
    public class RegisterModel
    {
        [Required(AllowEmptyStrings = false, ErrorMessage = "Provide Username.")]
        public string? username { get; set; }

        [Required]
        [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&_-])[A-Za-z\d@$!%*?&]{8,}$",
            ErrorMessage = "Password must be of eight characters minimum. The format rules? you already know.")]
        public string? password { get; set; }

        public string created_by { get; set; }

        public string? comments { get; set; }

        [Required]
        public string? authLevel { get; set; }
    }
}
