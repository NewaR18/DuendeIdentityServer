using DuendeIdentityServer;
using DuendeIdentityServer.Models;
using DuendeIdentityServer.Utilities;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using DuendeIdentityServer.Data;
using System;
using Duende.IdentityServer.Test;
using Microsoft.AspNetCore.Identity.UI.Services;
using DuendeIdentityServer.Utilities.EmailConfigurations;
using DuendeIdentityServer.Utilities.BuildModel;
using DuendeIdentityServer.Models.ViewModels;
using Duende.IdentityServer;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();
builder.Services.AddRazorPages();
var connString = builder.Configuration.GetConnectionString("IdentityConnection");
builder.Services.AddDbContext<ApplicationDbContext>(options => options.UseSqlServer(connString));
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options => options.SignIn.RequireConfirmedAccount = true).AddDefaultTokenProviders()
    .AddEntityFrameworkStores<ApplicationDbContext>();
builder.Services.AddSingleton<IEmailSender, EmailSender>();
builder.Services.AddScoped<CustomModelBuilder>();
builder.Services.Configure<MailDetailsViewModel>(builder.Configuration.GetSection("mailDetails"));
#region In-Memory Setup  --Commented
//builder.Services.AddIdentityServer()
//                    .AddInMemoryClients(Config.Clients)
//                    .AddInMemoryIdentityResources(Config.IdentityResources)
//                    //.AddInMemoryApiResources(Config.ApiResources)
//                    .AddInMemoryApiScopes(Config.ApiScopes)
//                    .AddTestUsers(Config.TestUsers)
//                    .AddDeveloperSigningCredential();
#endregion
var migrationsAssembly = typeof(Program).Assembly.GetName().Name;

builder.Services.AddIdentityServer()
    .AddConfigurationStore(options =>
    {
        options.ConfigureDbContext = b => b.UseSqlServer(connString,
            sql => sql.MigrationsAssembly(migrationsAssembly));
    })
    .AddOperationalStore(options =>
    {
        options.ConfigureDbContext = b => b.UseSqlServer(connString,
            sql => sql.MigrationsAssembly(migrationsAssembly));
    })
    .AddAspNetIdentity<ApplicationUser>();
builder.Services.AddAuthentication().AddGoogle(options =>
{
    options.ClientId = builder.Configuration["Authentication:Google:ClientId"];
    options.ClientSecret = builder.Configuration["Authentication:Google:ClientSecret"];
    options.Scope.Add("profile");
});
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
app.UseIdentityServer();
app.UseAuthentication();
app.UseAuthorization();
app.InitializeDatabase();
app.MapRazorPages().RequireAuthorization();
app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();