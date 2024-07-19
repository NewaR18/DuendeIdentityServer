using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.ModelBinding.Validation;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IdentityServer.Models
{
    public class ApplicationUser : IdentityUser
    {
        [Required]
        public string Name { get; set; }
        public string? Address { get; set; }
        public char Gender { get; set; }
        [ValidateNever]
        public string ImageURL { get; set; } = "";
        [ValidateNever]
        public string? EsewaName { get; set; } 
        [ValidateNever]
        public string? EsewaPhone { get; set; } 
    }
}
