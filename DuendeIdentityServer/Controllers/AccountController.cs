using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Globalization;
using System.Net;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Text;
using Microsoft.AspNetCore.Identity.UI.Services;
using Duende.IdentityServer.Events;
using Duende.IdentityServer.Models;
using Duende.IdentityServer;
using DuendeIdentityServer.Models.InputModel;
using DuendeIdentityServer.Utilities.BuildModel;
using DuendeIdentityServer.Models.ViewModels;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Stores;
using Microsoft.AspNetCore.Authentication;
using DuendeIdentityServer.Models.Options;
using DuendeIdentityServer.Utilities;
using Duende.IdentityServer.Extensions;
using IdentityModel;
using DuendeIdentityServer.Models;

namespace DuendeIdentityServer.Controllers
{
    public class AccountController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly CustomModelBuilder _customModelBuilder;
        private readonly IIdentityServerInteractionService _interaction;
        private readonly IAuthenticationSchemeProvider _schemeProvider;
        private readonly IClientStore _clientStore;
        private readonly IEventService _events;
        private readonly IEmailSender _emailSender;
        public AccountController(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            CustomModelBuilder customModelBuilder,
            IIdentityServerInteractionService interaction,
            IAuthenticationSchemeProvider schemeProvider,
            IEventService events,
            IClientStore clientStore,
            IEmailSender emailSender
            )
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _customModelBuilder = customModelBuilder;
            _interaction = interaction;
            _schemeProvider = schemeProvider;
            _clientStore = clientStore;
            _events = events;
            _emailSender = emailSender;
        }
        public async Task<IActionResult> Login(string? returnUrl)
        {
            LoginViewModel loginViewModel = await _customModelBuilder.BuildLoginViewModelAsync(returnUrl);

            if (loginViewModel.IsExternalLoginOnly)
            {
                // we only have one option for logging in and it's an external provider
                return RedirectToAction("Challenge", "External", new { scheme = loginViewModel.ExternalLoginScheme, returnUrl });
            }
            return View(loginViewModel);
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginInputModel model, string button)
        {
            var context = await _interaction.GetAuthorizationContextAsync(model.ReturnUrl);

            // the user clicked the "cancel" button
            if (button != "login")
            {
                if (context != null)
                {
                    // if the user cancels, send a result back into IdentityServer as if they 
                    // denied the consent (even if this client does not require consent).
                    // this will send back an access denied OIDC error response to the client.
                    await _interaction.DenyAuthorizationAsync(context, AuthorizationError.AccessDenied);

                    // we can trust model.ReturnUrl since GetAuthorizationContextAsync returned non-null
                    if (context.IsNativeClient())
                    {
                        // The client is native, so this change in how to
                        // return the response is for better UX for the end user.
                        return this.LoadingPage("Redirect", model.ReturnUrl);
                    }

                    return Redirect(model.ReturnUrl);
                }
                else
                {
                    // since we don't have a valid context, then we just go back to the home page
                    return Redirect("~/");
                }
            }

            if (ModelState.IsValid)
            {
                var result = await _signInManager.PasswordSignInAsync(model.Username, model.Password, model.RememberLogin, lockoutOnFailure: true);
                if (result.Succeeded)
                {
                    var user = await _userManager.FindByNameAsync(model.Username);
                    await _events.RaiseAsync(new UserLoginSuccessEvent(user.UserName, user.Id, user.UserName, clientId: context?.Client.ClientId));

                    if (context != null)
                    {
                        if (context.IsNativeClient())
                        {
                            // The client is native, so this change in how to
                            // return the response is for better UX for the end user.
                            return this.LoadingPage("Redirect", model.ReturnUrl);
                        }

                        // we can trust model.ReturnUrl since GetAuthorizationContextAsync returned non-null
                        return Redirect(model.ReturnUrl);
                    }

                    // request for a local page
                    if (Url.IsLocalUrl(model.ReturnUrl))
                    {
                        return Redirect(model.ReturnUrl);
                    }
                    else if (string.IsNullOrEmpty(model.ReturnUrl))
                    {
                        return Redirect("~/");
                    }
                    else
                    {
                        // user might have clicked on a malicious link - should be logged
                        throw new Exception("invalid return URL");
                    }
                }

                await _events.RaiseAsync(new UserLoginFailureEvent(model.Username, "invalid credentials", clientId: context?.Client.ClientId));
                ModelState.AddModelError(string.Empty, AccountOptions.InvalidCredentialsErrorMessage);
            }

            // something went wrong, show form with error
            LoginViewModel loginViewModel = await _customModelBuilder.BuildLoginViewModelAsync(model);
            return View(loginViewModel);
        }
        [HttpGet]
        public async Task<IActionResult> Logout(string logoutId)
        {
            // build a model so the logout page knows what to display
            bool? isAuthenticated = User?.Identity.IsAuthenticated;


            var logoutViewModel = await _customModelBuilder.BuildLogoutViewModelAsync(logoutId, isAuthenticated);

            if (logoutViewModel.ShowLogoutPrompt == false)
            {
                // if the request for logout was properly authenticated from IdentityServer, then
                // we don't need to show the prompt and can just log the user out directly.
                return await Logout(logoutViewModel);
            }

            return View(logoutViewModel);
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout(LogoutInputModel model)
        {
            var loggedOutViewModel = await _customModelBuilder.BuildLoggedOutViewModelAsync(model.LogoutId);
            if (User?.Identity.IsAuthenticated == true)
            {
                var idp = User.FindFirst(JwtClaimTypes.IdentityProvider)?.Value;
                if (idp != null && idp != IdentityServerConstants.LocalIdentityProvider)
                {
                    var providerSupportsSignout = await HttpContext.GetSchemeSupportsSignOutAsync(idp);
                    if (providerSupportsSignout)
                    {
                        if (loggedOutViewModel.LogoutId == null)
                        {
                            // if there's no current logout context, we need to create one
                            // this captures necessary info from the current logged in user
                            // before we signout and redirect away to the external IdP for signout
                            loggedOutViewModel.LogoutId = await _interaction.CreateLogoutContextAsync();
                        }

                        loggedOutViewModel.ExternalAuthenticationScheme = idp;
                    }
                }
            }
            if (User?.Identity.IsAuthenticated == true)
            {
                // delete local authentication cookie
                await _signInManager.SignOutAsync();

                // raise the logout event
                await _events.RaiseAsync(new UserLogoutSuccessEvent(User.GetSubjectId(), User.GetDisplayName()));
            }

            // check if we need to trigger sign-out at an upstream identity provider
            if (loggedOutViewModel.TriggerExternalSignout)
            {
                // build a return URL so the upstream provider will redirect back
                // to us after the user has logged out. this allows us to then
                // complete our single sign-out processing.
                string url = Url.Action("Logout", new { logoutId = loggedOutViewModel.LogoutId });

                // this triggers a redirect to the external provider for sign-out
                return SignOut(new AuthenticationProperties { RedirectUri = url }, loggedOutViewModel.ExternalAuthenticationScheme);
            }

            return View("LoggedOut", loggedOutViewModel);
        }
        public async Task<IActionResult> Register(string? returnUrl)
        {
            try
            {
                RegisterModel registerModel = new()
                {
                    Input = new RegisterInputModel(),
                    ReturnUrl = string.IsNullOrEmpty(returnUrl)?"": returnUrl,
                    ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList()
                };
                return View(registerModel);
            }
            catch
            {
                throw;
            }
        }
        [HttpPost]
        public async Task<IActionResult> Register(RegisterModel registerModel)
        {
            try
            {
                var context = await _interaction.GetAuthorizationContextAsync(registerModel.ReturnUrl);
                if (ModelState.IsValid)
                {
                    var user = CreateUser();
                    user.UserName = registerModel.Input.Username;
                    user.Email = registerModel.Input.Email;
                    user.PhoneNumber = registerModel.Input.PhoneNumber;
                    user.Name = registerModel.Input.Name;
                    user.Address = registerModel.Input.Address;
                    user.Gender = registerModel.Input.Gender;
                    var result = await _userManager.CreateAsync(user, registerModel.Input.Password);
                    if (result.Succeeded)
                    {
                        IEnumerable<string> RoleListEnumerable = new List<string>
                    {
                        "User"
                    };
                        var AddedToRole = await _userManager.AddToRolesAsync(user, RoleListEnumerable);
                        if (!AddedToRole.Succeeded)
                        {
                            foreach (var error in AddedToRole.Errors)
                            {
                                ModelState.AddModelError(string.Empty, error.Description);
                            }
                        }
                        if (_userManager.Options.SignIn.RequireConfirmedAccount)
                        {
                            return RedirectToAction(nameof(RegisterConfirmation), new { email = registerModel.Input.Email, redirectURL = registerModel.ReturnUrl});
                        }
                        else
                        {
                            await _signInManager.SignInAsync(user, isPersistent: true);
                            await _events.RaiseAsync(new UserLoginSuccessEvent(user.UserName, user.Id, user.UserName, clientId: context?.Client.ClientId));
                            if (context != null)
                            {
                                if (context.IsNativeClient())
                                {
                                    // The client is native, so this change in how to
                                    // return the response is for better UX for the end user.
                                    return this.LoadingPage("Redirect", registerModel.ReturnUrl);
                                }

                                // we can trust model.ReturnUrl since GetAuthorizationContextAsync returned non-null
                                return Redirect(registerModel.ReturnUrl);
                            }
                            // request for a local page
                            if (Url.IsLocalUrl(registerModel.ReturnUrl))
                            {
                                return Redirect(registerModel.ReturnUrl);
                            }
                            else if (string.IsNullOrEmpty(registerModel.ReturnUrl))
                            {
                                return Redirect("~/");
                            }
                            else
                            {
                                // user might have clicked on a malicious link - should be logged
                                throw new Exception("invalid return URL");
                            }
                        }
                    }
                    foreach (var error in result.Errors)
                    {
                        ModelState.AddModelError(string.Empty, error.Description);
                    }
                }
                registerModel.ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();
                return View(registerModel);
            }
            catch
            {
                throw;
            }
        }
        public async Task<IActionResult> RegisterConfirmation(string email, string redirectURL)
        {
            try
            {
                var user = await _userManager.FindByEmailAsync(email);
                if (user == null)
                {
                    return NotFound($"Unable to load user with email '{email}'.");
                }
                var userId = await _userManager.GetUserIdAsync(user);
                var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                var EmailConfirmationUrl = Url.Action(
                                        "ConfirmEmail",
                                        "Account",
                                        new { userId = userId, code = code, redirectURL = redirectURL },
                                        Request.Scheme
                                        );
                await _emailSender.SendEmailAsync(email, "Confirm your email",
                    $"Please confirm your account by <a href='{HtmlEncoder.Default.Encode(EmailConfirmationUrl)}'>clicking here</a>.");
                return View();
            }
            catch
            {
                throw;
            }
        }
        public async Task<IActionResult> ConfirmEmail(string userId, string code, string redirectURL)
        {
            try
            {
                var context = await _interaction.GetAuthorizationContextAsync(redirectURL);
                if (userId == null || code == null)
                {
                    TempData["error"] = "Email could not be verified";
                    return RedirectToAction("Index", "Account", new { area = "Bills" });
                }
                var user = await _userManager.FindByIdAsync(userId);
                if (user == null)
                {
                    TempData["error"] = "User not found";
                    return RedirectToAction("Index", "Account", new { area = "Bills" });
                }
                var result = await _userManager.ConfirmEmailAsync(user, code);
                if (result.Succeeded)
                {
                    TempData["success"] = "Email Confirmed";
                }
                else
                {
                    TempData["error"] = "Email Confirmation failure";
                }
                await _signInManager.SignInAsync(user, isPersistent: true);
                await _events.RaiseAsync(new UserLoginSuccessEvent(user.UserName, user.Id, user.UserName, clientId: context?.Client.ClientId));
                if (context != null)
                {
                    if (context.IsNativeClient())
                    {
                        // The client is native, so this change in how to
                        // return the response is for better UX for the end user.
                        return this.LoadingPage("Redirect", redirectURL);
                    }

                    // we can trust model.ReturnUrl since GetAuthorizationContextAsync returned non-null
                    return Redirect(redirectURL);
                }
                // request for a local page
                if (Url.IsLocalUrl(redirectURL))
                {
                    return Redirect(redirectURL);
                }
                else if (string.IsNullOrEmpty(redirectURL))
                {
                    return Redirect("~/");
                }
                else
                {
                    // user might have clicked on a malicious link - should be logged
                    throw new Exception("invalid return URL");
                }
            }
            catch
            {
                throw;
            }
        }
        private ApplicationUser CreateUser()
        {
            try
            {
                return Activator.CreateInstance<ApplicationUser>();
            }
            catch
            {
                throw new InvalidOperationException($"Can't create an instance of '{nameof(IdentityUser)}'. " +
                    $"Ensure that '{nameof(IdentityUser)}' is not an abstract class and has a parameterless constructor, or alternatively " +
                    $"override the register page in /Areas/AccountManager/Account/Register.cshtml");
            }
        }
        [HttpGet]
        public IActionResult ForgetPassword(string redirectURL)
        {
            ForgetPasswordViewModel forgetPasswordViewModel = new ForgetPasswordViewModel()
            {
                Email = "",
                ReturnUrl = redirectURL
            };
            return View(forgetPasswordViewModel);
        }
        [HttpPost]
        public async Task<IActionResult> ForgetPassword(ForgetPasswordViewModel forgetPassword)
        {
            try
            {
                if (ModelState.IsValid)
                {
                    var user = await _userManager.FindByEmailAsync(forgetPassword.Email);
                    if (user == null || !(await _userManager.IsEmailConfirmedAsync(user)))
                    {
                        TempData["error"] = "Could not reset the password";
                        return View();
                    }
                    var code = await _userManager.GeneratePasswordResetTokenAsync(user);
                    //code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));
                    var EmailConfirmationUrl = Url.Action(
                                        "ResetPassword",
                                        "Account",
                                        new { code = code, email = forgetPassword.Email, returnURL = forgetPassword.ReturnUrl },
                                        Request.Scheme
                                        );
                    await _emailSender.SendEmailAsync(
                        forgetPassword.Email,
                        "Reset Password",
                        $"Please reset your password by <a href='{HtmlEncoder.Default.Encode(EmailConfirmationUrl)}'>clicking here</a>.");
                    return RedirectToAction(nameof(ForgetPasswordConfirmation));
                }
                return View();
            }
            catch
            {
                throw;
            }
        }
        
        public IActionResult ForgetPasswordConfirmation()
        {
            return View();
        }
        
        public IActionResult ResetPassword(string code = null, string email = null, string returnURL = null)
        {
            if (code == null || email == null)
            {
                TempData["error"] = "Problem occurred while resetting the password";
                return RedirectToAction("Login");
            }
            else
            {
                ResetPasswordViewModel model = new ResetPasswordViewModel();
                model.Code = code;
                model.Email = email;
                model.ReturnUrl = string.IsNullOrEmpty(returnURL) ? "": returnURL;
                return View(model);
            }
        }
        [HttpPost]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return View();
                }
                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user == null)
                {
                    TempData["error"] = "Could not reset password";
                    return RedirectToAction(nameof(Login));
                }
                var result = await _userManager.ResetPasswordAsync(user, model.Code, model.Password);
                if (result.Succeeded)
                {
                    var context = await _interaction.GetAuthorizationContextAsync(model.ReturnUrl);
                    await _events.RaiseAsync(new UserLoginSuccessEvent(user.UserName, user.Id, user.UserName, clientId: context?.Client.ClientId));
                    if (context != null)
                    {
                        if (context.IsNativeClient())
                        {
                            // The client is native, so this change in how to
                            // return the response is for better UX for the end user.
                            return this.LoadingPage("Redirect", model.ReturnUrl);
                        }

                        // we can trust model.ReturnUrl since GetAuthorizationContextAsync returned non-null
                        return Redirect(model.ReturnUrl);
                    }
                    // request for a local page
                    if (Url.IsLocalUrl(model.ReturnUrl))
                    {
                        return Redirect(model.ReturnUrl);
                    }
                    else if (string.IsNullOrEmpty(model.ReturnUrl))
                    {
                        return Redirect("~/");
                    }
                    else
                    {
                        return RedirectToAction(nameof(ResetPasswordConfirmation));
                    }
                    
                }
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
                return View();
            }
            catch
            {
                throw;
            }
        }
        public IActionResult ResetPasswordConfirmation()
        {
            return View();
        }
        
        public IActionResult ExternalLogin(string scheme, string returnUrl = null)
        {
            try
            {
                var redirectUrl = Url.Action("Callback", "Account", new {redirectUrl = returnUrl });
                var properties = _signInManager.ConfigureExternalAuthenticationProperties(scheme, redirectUrl);
                return new ChallengeResult(scheme, properties);
            }
            catch
            {
                throw;
            }
        }

        public async Task<IActionResult> Callback(string redirectUrl, string remoteError = null)
        {
            try
            {
                var context = await _interaction.GetAuthorizationContextAsync(redirectUrl);
                if (remoteError != null)
                {
                    TempData["error"] = $"Error from external provider: {remoteError}";
                    return RedirectToAction(nameof(Login));
                }
                var info = await _signInManager.GetExternalLoginInfoAsync();
                if (info == null)
                {
                    TempData["error"] = "Error loading external login information.";
                    return RedirectToAction(nameof(Login));
                }
                var result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false, bypassTwoFactor: true);
                if (result.Succeeded)
                {
                    TempData["success"] = "Logged In using Google";
                    if (context != null)
                    {
                        if (context.IsNativeClient())
                        {
                            // The client is native, so this change in how to
                            // return the response is for better UX for the end user.
                            return this.LoadingPage("Redirect", redirectUrl);
                        }

                        // we can trust model.ReturnUrl since GetAuthorizationContextAsync returned non-null
                        return Redirect(redirectUrl);
                    }
                    // request for a local page
                    if (Url.IsLocalUrl(redirectUrl))
                    {
                        return Redirect(redirectUrl);
                    }
                    else if (string.IsNullOrEmpty(redirectUrl))
                    {
                        return Redirect("~/");
                    }
                    else
                    {
                        return RedirectToAction(nameof(ResetPasswordConfirmation));
                    }
                }
                if (result.IsLockedOut)
                {
                    return RedirectToAction("Lockout");
                }
                else
                {
                    ExternalLoginViewModel externalLoginModel = new ExternalLoginViewModel();
                    externalLoginModel.ProviderDisplayName = info.ProviderDisplayName;
                    externalLoginModel.ReturnUrl = redirectUrl;
                    if (info.Principal.HasClaim(c => c.Type == ClaimTypes.Email))
                    {
                        externalLoginModel.Input = new ExternalLoginInput
                        {
                            Email = info.Principal.FindFirstValue(ClaimTypes.Email),
                            Name = info.Principal.FindFirstValue(ClaimTypes.Name)
                        };
                    }
                    return View(nameof(ExternalLogin), externalLoginModel);
                }
            }
            catch
            {
                throw;
            }
        }
        public async Task<IActionResult> ConfirmationExternalAuthentication(ExternalLoginViewModel externalLoginModel)
        {
            try
            {
                var context = await _interaction.GetAuthorizationContextAsync(externalLoginModel.ReturnUrl);
                var info = await _signInManager.GetExternalLoginInfoAsync();
                if (info == null)
                {
                    TempData["error"] = "Error loading external login information during confirmation.";
                    return RedirectToAction(nameof(Login));
                }

                if (ModelState.IsValid)
                {
                    var user = CreateUser();
                    user.UserName = externalLoginModel.Input.Email;
                    user.Email = externalLoginModel.Input.Email;
                    TextInfo ti = CultureInfo.CurrentCulture.TextInfo;
                    user.Name = ti.ToTitleCase(externalLoginModel.Input.Name);
                    var result = await _userManager.CreateAsync(user);
                    if (result.Succeeded)
                    {
                        result = await _userManager.AddLoginAsync(user, info);
                        if (result.Succeeded)
                        {
                            ApplicationUser _identityuser = _userManager.Users.Where(s => s.Email == externalLoginModel.Input.Email).FirstOrDefault();
                            _identityuser.EmailConfirmed = true;
                            await _userManager.UpdateAsync(_identityuser);
                            await _signInManager.SignInAsync(user, isPersistent: false, info.LoginProvider);
                            if (context != null)
                            {
                                if (context.IsNativeClient())
                                {
                                    // The client is native, so this change in how to
                                    // return the response is for better UX for the end user.
                                    return this.LoadingPage("Redirect", externalLoginModel.ReturnUrl);
                                }

                                // we can trust model.ReturnUrl since GetAuthorizationContextAsync returned non-null
                                return Redirect(externalLoginModel.ReturnUrl);
                            }
                            // request for a local page
                            if (Url.IsLocalUrl(externalLoginModel.ReturnUrl))
                            {
                                return Redirect(externalLoginModel.ReturnUrl);
                            }
                            else if (string.IsNullOrEmpty(externalLoginModel.ReturnUrl))
                            {
                                return Redirect("~/");
                            }
                            else
                            {
                                return RedirectToAction(nameof(ResetPasswordConfirmation));
                            }
                        }
                    }
                    foreach (var error in result.Errors)
                    {
                        ModelState.AddModelError(string.Empty, error.Description);
                    }
                }
                return View(nameof(ExternalLogin), externalLoginModel);
            }
            catch
            {
                throw;
            }
        }
        /*
        public async Task<IActionResult> ConfirmationExternalAuthentication(ExternalLoginModel externalLoginModel)
        {
            try
            {
                var info = await _signInManager.GetExternalLoginInfoAsync();
                if (info == null)
                {
                    TempData["error"] = "Error loading external login information during confirmation.";
                    return RedirectToAction(nameof(Login));
                }

                if (ModelState.IsValid)
                {
                    var user = CreateUser();
                    user.UserName = externalLoginModel.Input.Email;
                    user.Email = externalLoginModel.Input.Email;
                    TextInfo ti = CultureInfo.CurrentCulture.TextInfo;
                    user.Name = ti.ToTitleCase(externalLoginModel.Input.Name);
                    var result = await _userManager.CreateAsync(user);
                    if (result.Succeeded)
                    {
                        result = await _userManager.AddLoginAsync(user, info);
                        if (result.Succeeded)
                        {
                            ApplicationUser _identityuser = _userManager.Users.Where(s => s.Email == externalLoginModel.Input.Email).FirstOrDefault();
                            _identityuser.EmailConfirmed = true;
                            await _userManager.UpdateAsync(_identityuser);
                            await _signInManager.SignInAsync(user, isPersistent: false, info.LoginProvider);
                            return RedirectToAction(nameof(HomeController.Index), "Home", new { area = "Bills" });
                        }
                    }
                    foreach (var error in result.Errors)
                    {
                        ModelState.AddModelError(string.Empty, error.Description);
                    }
                }
                return View(nameof(ExternalLogin), externalLoginModel);
            }
            catch
            {
                throw;
            }
        }
        
                #region Profile
                public async Task<IActionResult> Profile()
                {
                    try
                    {
                        var user = await _userManager.GetUserAsync(User);

                        ProfileIndexModel profileData = new ProfileIndexModel()
                        {
                            Name = user.Name,
                            Email = user.Email,
                            Address = user.Address,
                            Gender = user.Gender,
                            PhoneNumber = user.PhoneNumber,
                            ImageURL = user.ImageURL,
                            EsewaName = user.EsewaName,
                            EsewaPhone = user.EsewaPhone
                        };
                        return View(profileData);
                    }
                    catch
                    {
                        throw;
                    }
                }
                [HttpPost]
                public async Task<IActionResult> Profile(ProfileIndexModel profileData, IFormFile? file)
                {
                    try
                    {
                        var user = await _userManager.FindByEmailAsync(profileData.Email);
                        if (ModelState.IsValid)
                        {
                            if (file != null)
                            {
                                string wwwRootPath = _webHostEnvironment.WebRootPath;
                                string FileName = Guid.NewGuid().ToString();
                                var FilePath = Path.Combine(wwwRootPath, "images/users");
                                var FileExtension = Path.GetExtension(file.FileName);
                                var FinalPath = Path.Combine(FilePath, FileName + FileExtension);
                                if (profileData.ImageURL != null)
                                {
                                    var FileToBeDeleted = Path.Combine(wwwRootPath, profileData.ImageURL.TrimStart('/'));
                                    if (System.IO.File.Exists(FileToBeDeleted))
                                    {
                                        System.IO.File.Delete(FileToBeDeleted);
                                    }
                                }
                                using (var fileStream = new FileStream(FinalPath, FileMode.Create))
                                {
                                    file.CopyTo(fileStream);
                                }
                                user.ImageURL = @"/images/users/" + FileName + FileExtension;
                                profileData.ImageURL = user.ImageURL;
                            }
                            user.Name = profileData.Name;
                            user.Address = profileData.Address;
                            user.Gender = profileData.Gender;
                            user.PhoneNumber = profileData.PhoneNumber;
                            user.EsewaName = profileData.EsewaName?.Trim();
                            user.EsewaPhone = profileData.EsewaPhone?.Trim();
                            var result = await _userManager.UpdateAsync(user);
                            if (result.Succeeded)
                            {
                                TempData["success"] = "User Updated Successfully";
                                return RedirectToAction(nameof(Profile));
                            }
                            else
                            {
                                foreach (var error in result.Errors)
                                {
                                    ModelState.AddModelError(string.Empty, error.Description);
                                }
                            }
                        }
                        return View();
                    }
                    catch
                    {
                        throw;
                    }
                }
                public async Task<IActionResult> SetPassword()
                {
                    try
                    {
                        var user = await _userManager.GetUserAsync(User);
                        if (user == null)
                        {
                            TempData["error"] = "Error occured! Login again to set password";
                            return RedirectToAction(nameof(Profile));
                        }
                        var hasPassword = await _userManager.HasPasswordAsync(user);
                        if (hasPassword)
                        {
                            return RedirectToAction(nameof(ChangePassword));
                        }
                        return View();
                    }
                    catch
                    {
                        throw;
                    }
                }
                [HttpPost]
                public async Task<IActionResult> SetPassword(SetPasswordModel setPassword)
                {
                    try
                    {
                        if (!ModelState.IsValid)
                        {
                            return View();
                        }
                        var user = await _userManager.GetUserAsync(User);
                        if (user == null)
                        {
                            TempData["error"] = "Error occured! Login again to set password";
                            return RedirectToAction(nameof(Profile));
                        }
                        var addPasswordResult = await _userManager.AddPasswordAsync(user, setPassword.NewPassword);
                        if (!addPasswordResult.Succeeded)
                        {
                            foreach (var error in addPasswordResult.Errors)
                            {
                                ModelState.AddModelError(string.Empty, error.Description);
                            }
                            return View();
                        }
                        await _signInManager.RefreshSignInAsync(user);
                        TempData["success"] = "Your Password has been set";
                        return RedirectToAction(nameof(Profile));
                    }
                    catch
                    {
                        throw;
                    }
                }
                public async Task<IActionResult> ChangePassword()
                {
                    try
                    {
                        var user = await _userManager.GetUserAsync(User);
                        if (user == null)
                        {
                            TempData["error"] = "Error occured! Login again to set password";
                            return RedirectToAction(nameof(Profile));
                        }
                        var hasPassword = await _userManager.HasPasswordAsync(user);
                        if (!hasPassword)
                        {
                            return RedirectToAction(nameof(SetPassword));
                        }
                        return View();
                    }
                    catch
                    {
                        throw;
                    }
                }
                
        */
    }
}
