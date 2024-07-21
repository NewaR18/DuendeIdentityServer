using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DuendeIdentityServer.Models.ViewModels
{
    public class ForgetPasswordViewModel
    {
        public string Email { get; set; }
        public string ReturnUrl { get; set; }
    }
}
