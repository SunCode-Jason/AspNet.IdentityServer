using Duende.IdentityServer;
using Duende.IdentityServer.Models;
using IdentityModel;

namespace IdentityServer;

public static class Config
{
    /// <summary>
    ///  身份资源
    /// </summary>
    public static IEnumerable<IdentityResource> IdentityResources =>
        new IdentityResource[]
        {
            new IdentityResources.OpenId(),
            new IdentityResources.Profile(),
            /*
                定义名称为：email的资源
                客户端通过scope值， 获取关联的 UserClaims
             */
            new IdentityResource(){
                Name = "email", // 
                UserClaims = [
                JwtClaimTypes.Email,
                JwtClaimTypes.EmailVerified
                ]
            }
        };

    public static IEnumerable<ApiScope> ApiScopes =>
        new ApiScope[]
            {
                new ApiScope(name: "api1", displayName: "My API")
            };

    public static IEnumerable<Client> Clients =>
        new Client[]
            {
        // machine to machine client (from quickstart 1)
        new Client
        {
            ClientId = "client",

            // no interactive user, use the clientid/secret for authentication
            AllowedGrantTypes = GrantTypes.ClientCredentials,

            // secret for authentication
            ClientSecrets =
            {
                new Secret("secret".Sha256())
            },

            // scopes that client has access to
            AllowedScopes = { "api1" }
        },
        // interactive ASP.NET Core Web App
        new Client
        {
            ClientId = "web",
            ClientSecrets = { new Secret("secret".Sha256()) },

            AllowedGrantTypes = GrantTypes.Code,
            
            // where to redirect to after login
            RedirectUris = { "https://localhost:5002/signin-oidc" },

            // where to redirect to after logout
            PostLogoutRedirectUris = { "https://localhost:5002/signout-callback-oidc" },
            // 允许客户端刷新令牌
            AllowOfflineAccess = true,
            // 指定客户端可访问的资源
            AllowedScopes =
            {
                IdentityServerConstants.StandardScopes.OpenId,
                IdentityServerConstants.StandardScopes.Profile,
                "email",
                "api1"
            }
        }
    };
}