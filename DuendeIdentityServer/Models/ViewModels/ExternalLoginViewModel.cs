using Microsoft.AspNetCore.Mvc.ModelBinding.Validation;
using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;

namespace DuendeIdentityServer.Models.ViewModels
{
    public class ExternalLoginViewModel
    {
        [BindProperty]
        public ExternalLoginInput Input { get; set; }
        [ValidateNever]
        public string ProviderDisplayName { get; set; }
        public string ReturnUrl { get; set; }
    }
    public class ExternalLoginInput
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
        [Required]
        public string Name { get; set; }
    }
}
