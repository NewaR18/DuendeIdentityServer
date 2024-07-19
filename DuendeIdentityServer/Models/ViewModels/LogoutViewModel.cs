using DuendeIdentityServer.Models.InputModel;

namespace DuendeIdentityServer.Models.ViewModels
{
    public class LogoutViewModel : LogoutInputModel
    {
        public bool ShowLogoutPrompt { get; set; } = true;
    }
}
