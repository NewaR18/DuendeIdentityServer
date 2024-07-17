namespace Cinemas.Client.Models.ViewModels
{
    public class UserInfoViewModel
    {
        public Dictionary<string, string> UserInfoDictionary { get; private set; }
        public UserInfoViewModel(Dictionary<string, string> userInfoDictionary)
        {
            UserInfoDictionary = userInfoDictionary;
        }
    }
}
