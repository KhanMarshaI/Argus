using System.ComponentModel.DataAnnotations;

namespace ArgusFrontend.Models
{
    public class ProfileModel
    {
        [Required(AllowEmptyStrings = false, ErrorMessage = "Provide username.")]
        public string? Username { get; set; }

        [Required(AllowEmptyStrings = false, ErrorMessage = "Provide current password.")]
        public string? CurrentPassword { get; set; }

        [Required(AllowEmptyStrings = false, ErrorMessage = "Provide new password.")]
        public string? NewPassword { get; set; }

        [Required(AllowEmptyStrings = false, ErrorMessage = "Provide confirm password.")]
        public string? ConfirmPassword { get; set; }
    }
}
