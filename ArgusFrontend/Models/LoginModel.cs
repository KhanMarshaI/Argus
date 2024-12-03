using System.ComponentModel.DataAnnotations;

namespace ArgusFrontend.Models
{
    public class LoginModel
    {
        [Required(AllowEmptyStrings=false, ErrorMessage ="Provide username.")]
        public string? Username { get; set; }

        [Required(AllowEmptyStrings = false, ErrorMessage = "Provide password.")]
        public string? Password { get; set; }

        public string? authLevel { get; set; }
    }
}
