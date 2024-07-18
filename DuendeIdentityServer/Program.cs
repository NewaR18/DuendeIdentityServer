using IdentityServer;
using IdentityServer.Utilities;
using IdentityServerHost;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();
builder.Services.AddRazorPages();
//builder.Services.AddIdentityServer()
//                    .AddInMemoryClients(Config.Clients)
//                    .AddInMemoryIdentityResources(Config.IdentityResources)
//                    //.AddInMemoryApiResources(Config.ApiResources)
//                    .AddInMemoryApiScopes(Config.ApiScopes)
//                    .AddTestUsers(Config.TestUsers)
//                    .AddDeveloperSigningCredential();
var migrationsAssembly = typeof(Program).Assembly.GetName().Name;
var connString = builder.Configuration.GetConnectionString("IdentityConnection");

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
    .AddTestUsers(Config.TestUsers);
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
app.UseAuthorization();
app.InitializeDatabase();
app.MapRazorPages().RequireAuthorization();
app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
