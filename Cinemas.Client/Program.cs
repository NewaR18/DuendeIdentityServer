using Cinemas.Client.Helpers.HttpHandler;
using Cinemas.Client.Helpers.Modules;
using IdentityModel;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Net.Http.Headers;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
})
    .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
    {
        options.Authority = builder.Configuration["BaseIdentityURL"];
        options.ClientId = "movies_mvc_another_client";
        options.ClientSecret = "secret";
        options.ResponseType = "code id_token";
        //options.Scope.Add("openid");
        //options.Scope.Add("profile"); //Added automatically, no need to mention it
        options.Scope.Add("address");
        options.Scope.Add("email");
        options.Scope.Add("phone");
        options.Scope.Add("roles");
        //options.Scope.Add("moviesAPI2"); //var hasReadScope = User.HasClaim("scope", "api1.read"); Can be used in this way in Controller to see if user has read/write access
        options.ClaimActions.MapUniqueJsonKey(nameof(JwtClaimTypes.Role), "role");
        options.ClaimActions.MapUniqueJsonKey(nameof(JwtClaimTypes.PhoneNumber), "phoneNumber");


        options.SaveTokens = true;
        options.GetClaimsFromUserInfoEndpoint = true;
        options.TokenValidationParameters = new TokenValidationParameters()
        {
            NameClaimType = JwtClaimTypes.Name,
            RoleClaimType = JwtClaimTypes.Role
        };
    });
builder.Services.RegisterServices(builder.Configuration);
builder.Services.AddHttpClient("MovieAPIClient", client =>
{
    client.BaseAddress = new Uri(builder.Configuration["APIURL"] ?? string.Empty);
    client.DefaultRequestHeaders.Clear();
    client.DefaultRequestHeaders.Add(HeaderNames.Accept, "application/json");
}).AddHttpMessageHandler<AuthenticationDelegatingHandler>();
builder.Services.AddHttpClient("IdentityServerClient", client =>
{
    client.BaseAddress = new Uri(builder.Configuration["BaseIdentityURL"] ?? string.Empty);
    client.DefaultRequestHeaders.Clear();
    client.DefaultRequestHeaders.Add(HeaderNames.Accept, "application/json");
});
builder.Services.AddHttpContextAccessor();
var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
