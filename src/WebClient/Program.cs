using Microsoft.AspNetCore.Authentication;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorPages();

builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = "Cookies";
    options.DefaultChallengeScheme = "oidc";
})
    .AddCookie("Cookies")
    .AddOpenIdConnect("oidc", options =>
    {
        options.Authority = "https://localhost:5001";

        options.ClientId = "web";
        options.ClientSecret = "secret";
        options.ResponseType = "code";

        options.Scope.Clear();
        options.Scope.Add("openid");
        options.Scope.Add("profile");
        options.Scope.Add("api1");
        options.Scope.Add("offline_access"); // 
        options.Scope.Add("email");
        options.ClaimActions.MapJsonKey("email_verified_jason", "email_verified");


        options.GetClaimsFromUserInfoEndpoint = true; // additional user claims associated with the profile identity scope displayed 

        options.MapInboundClaims = false; // Don't rename claim types

        options.SaveTokens = true;
    });
// install Duende.AccessTokenManagement.OpenIdConnect
builder.Services.AddOpenIdConnectAccessTokenManagement();

builder.Services.AddUserAccessTokenHttpClient("apiClient", configureClient: client =>
{
    client.BaseAddress = new Uri("https://localhost:6001");
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();

app.UseRouting();

app.UseAuthentication();

app.UseAuthorization();

app.MapStaticAssets();
app.MapRazorPages()
   .WithStaticAssets()
   .RequireAuthorization();

app.Run();
