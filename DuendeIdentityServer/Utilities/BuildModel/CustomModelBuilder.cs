using Duende.IdentityServer;
using Duende.IdentityServer.EntityFramework.Stores;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Stores;
using DuendeIdentityServer.Models.InputModel;
using DuendeIdentityServer.Models.Options;
using DuendeIdentityServer.Models.OtherModels;
using DuendeIdentityServer.Models.ViewModels;
using IdentityModel;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
using Microsoft.VisualBasic;

namespace DuendeIdentityServer.Utilities.BuildModel
{
    public class CustomModelBuilder
    {
        private readonly IIdentityServerInteractionService _interaction;
        private readonly IAuthenticationSchemeProvider _schemeProvider;
        private readonly IIdentityProviderStore _identityProviderStore;
        private readonly IClientStore _clientStore;
        public CustomModelBuilder(IIdentityServerInteractionService interaction,
                                    IAuthenticationSchemeProvider schemeProvider,
                                    IIdentityProviderStore identityProviderStore,
                                    IClientStore clientStore) 
        {
            _interaction = interaction;
            _schemeProvider = schemeProvider;
            _identityProviderStore = identityProviderStore;
            _clientStore = clientStore;
        }
        public async Task<LoginViewModel> BuildLoginViewModelAsync(string? returnUrl)
        {
            var context = await _interaction.GetAuthorizationContextAsync(returnUrl);
            if (context?.IdP != null && await _schemeProvider.GetSchemeAsync(context.IdP) != null)
            {
                var local = context.IdP == IdentityServerConstants.LocalIdentityProvider; 

                // this is meant to short circuit the UI and only trigger the one external IdP
                var loginViewModel = new LoginViewModel
                {
                    EnableLocalLogin = local,
                    ReturnUrl = returnUrl,
                    Username = context?.LoginHint,
                };

                if (!local)
                {
                    loginViewModel.ExternalProviders = new[] { new ExternalProvider { AuthenticationScheme = context.IdP } };
                }

                return loginViewModel;
            }

            var schemes = await _schemeProvider.GetAllSchemesAsync();

            var providers = schemes
                .Where(x => x.DisplayName != null)
                .Select(x => new ExternalProvider
                {
                    DisplayName = x.DisplayName ?? x.Name,
                    AuthenticationScheme = x.Name
                }).ToList();

            var allowLocal = true;
            if (context?.Client.ClientId != null)
            {
                var client = await _clientStore.FindEnabledClientByIdAsync(context.Client.ClientId);
                if (client != null)
                {
                    allowLocal = client.EnableLocalLogin;

                    if (client.IdentityProviderRestrictions != null && client.IdentityProviderRestrictions.Any())
                    {
                        providers = providers.Where(provider => client.IdentityProviderRestrictions.Contains(provider.AuthenticationScheme)).ToList();
                    }
                }
            }

            return new LoginViewModel
            {
                AllowRememberLogin = AccountOptions.AllowRememberLogin,
                EnableLocalLogin = allowLocal && AccountOptions.AllowLocalLogin,
                ReturnUrl = returnUrl,
                Username = context?.LoginHint,
                ExternalProviders = providers.ToArray()
            };
        }
        public async Task<LoginViewModel> BuildLoginViewModelAsync(LoginInputModel model)
        {
            var loginViewModel = await BuildLoginViewModelAsync(model.ReturnUrl);
            loginViewModel.Username = model.Username;
            loginViewModel.RememberLogin = model.RememberLogin;
            return loginViewModel;
        }
        public async Task<LogoutViewModel> BuildLogoutViewModelAsync(string logoutId,bool? isAuthenticated)
        {
            var logoutViewModel = new LogoutViewModel { LogoutId = logoutId, ShowLogoutPrompt = AccountOptions.ShowLogoutPrompt };

            if (isAuthenticated != true)
            {
                // if the user is not authenticated, then just show logged out page
                logoutViewModel.ShowLogoutPrompt = false;
                return logoutViewModel;
            }

            var context = await _interaction.GetLogoutContextAsync(logoutId);
            if (context?.ShowSignoutPrompt == false)
            {
                // it's safe to automatically sign-out
                logoutViewModel.ShowLogoutPrompt = false;
                return logoutViewModel;
            }

            // show the logout prompt. this prevents attacks where the user
            // is automatically signed out by another malicious web page.
            return logoutViewModel;
        }
        public async Task<LoggedOutViewModel> BuildLoggedOutViewModelAsync(string logoutId)
        {
            // get context information (client name, post logout redirect URI and iframe for federated signout)
            var logout = await _interaction.GetLogoutContextAsync(logoutId);

            var loggedOutViewModel = new LoggedOutViewModel
            {
                AutomaticRedirectAfterSignOut = AccountOptions.AutomaticRedirectAfterSignOut,
                PostLogoutRedirectUri = logout?.PostLogoutRedirectUri,
                ClientName = string.IsNullOrEmpty(logout?.ClientName) ? logout?.ClientId : logout?.ClientName,
                SignOutIframeUrl = logout?.SignOutIFrameUrl,
                LogoutId = logoutId
            };
            return loggedOutViewModel;
        }
    }
}
