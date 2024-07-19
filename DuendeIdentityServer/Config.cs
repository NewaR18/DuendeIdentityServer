using Duende.IdentityServer;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Test;
using IdentityModel;
using System.Security.Claims;
using System.Security.Cryptography;

namespace DuendeIdentityServer
{
    public class Config
    {
        #region OldWay
            //public static IEnumerable<Client> GetClients()
            //{
            //    return new List<Client>
            //    {
            //        new Client
            //        {
            //            ClientId = "client",
            //            AllowedGrantTypes = GrantTypes.ClientCredentials,
            //            ClientSecrets =
            //            {
            //                new Secret("secret".Sha256())
            //            },
            //            AllowedScopes = { "api1" }
            //        }
            //    };
            //}
        #endregion
        public static IEnumerable<Client> Clients =>
            new List<Client>
            {
                new Client
                {
                    ClientId = "movieClient",
                    AllowedGrantTypes = GrantTypes.ClientCredentials,
                    ClientSecrets =
                    {
                        new Secret("@Mjail11S".Sha256())
                    },
                    AllowedScopes = { "moviesAPI" }
                },
                new Client
                {
                    ClientId="movies_mvc_client",
                    ClientName="Movies MVC Web App",
                    AllowedGrantTypes= GrantTypes.Code,
                    AllowRememberConsent = false,
                    RedirectUris = new List<string>()
                    {
                        "https://localhost:7002/signin-oidc"
                    },
                    PostLogoutRedirectUris = new List<string>()
                    {
                        "https://localhost:7002/signout-callback-oidc"
                    },
                    ClientSecrets = new List<Secret>()
                    {
                        new Secret("secret".Sha256())
                    },
                    AllowedScopes = new List<string>()
                    {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile
                        //,"moviesAPI2"
                    }
                },
                new Client
                {
                    ClientId="movies_mvc_another_client",
                    ClientName="Another Web App",
                    AllowedGrantTypes= GrantTypes.Hybrid,
                    RequirePkce = false, //needed for hybrid flow
                    AllowRememberConsent = false,
                    AllowAccessTokensViaBrowser = true, //Needed if you are trying to access access_token too, not needed in case of id_token
                    RedirectUris = new List<string>()
                    {
                        "https://localhost:7003/signin-oidc"
                    },
                    PostLogoutRedirectUris = new List<string>()
                    {
                        "https://localhost:7003/signout-callback-oidc"
                    },
                    ClientSecrets = new List<Secret>()
                    {
                        new Secret("secret".Sha256())
                    },
                    AllowedScopes = new List<string>()
                    {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        IdentityServerConstants.StandardScopes.Email,
                        IdentityServerConstants.StandardScopes.Phone,
                        IdentityServerConstants.StandardScopes.Address,
                        "roles"
                        //,"moviesAPI2" //In order to access Movies API using access token of Authorization Code
                    }
                }

            };

        #region OldWay
        //public static IEnumerable<ApiResource> GetApiResources()
        //{
        //    return new List<ApiResource>
        //    {
        //        new ApiResource("api1", "My API")
        //    };
        //}
        #endregion
        public static IEnumerable<ApiResource> ApiResources =>
            new ApiResource[]
            {
                new ApiResource("api1", "My API")
            };

        #region OldWay
        //public static IEnumerable<ApiScope> GetApiScopes()
        //{
        //    return new List<ApiScope>
        //    {
        //        new ApiScope("api1.read", "Read access to API 1"),
        //        new ApiScope("api1.write", "Write access to API 1")
        //    };
        //}
        #endregion
        public static IEnumerable<ApiScope> ApiScopes =>
            new ApiScope[]
            {
                new ApiScope("moviesAPI", "Movie API"), //Not used
                new ApiScope("moviesAPI2", "Movie API2") //Not Used
            };

        #region Oldway
        //public static IEnumerable<IdentityResource> GetIdentityResources()
        //{
        //    return new List<IdentityResource>
        //    {
        //        new IdentityResources.OpenId(),
        //        new IdentityResources.Profile(),
        //    };
        //}
        #endregion
        public static IEnumerable<IdentityResource> IdentityResources =>
            new IdentityResource[]
            {
                new IdentityResources.OpenId(),
                new IdentityResources.Profile(),
                new IdentityResources.Address(),
                new IdentityResources.Email(),
                new IdentityResources.Phone(),
                new IdentityResource("roles","Roles", new List<string>(){"role"})
            };
        #region OldWay
        //public static List<TestUser> GetUsers()
        //{
        //    return new List<TestUser>
        //        {
        //            new TestUser
        //            {
        //                SubjectId = "1",
        //                Username = "alice",
        //                Password = "password"
        //            },
        //            new TestUser
        //            {
        //                SubjectId = "2",
        //                Username = "bob",
        //                Password = "password"
        //            }
        //        };
        //}
        #endregion
        public static List<TestUser> TestUsers =>
            new List<TestUser>
            {
                new TestUser
                {
                    SubjectId = "89A9F24C-0898-4B27-A3E8-60D51488854B",
                    Username = "sudip",
                    Password = "password",
                    Claims = new List<Claim>()
                    {
                        new Claim(JwtClaimTypes.Name, "Sudip Shrestha"),
                        new Claim(JwtClaimTypes.GivenName,"sudip"),
                        new Claim(JwtClaimTypes.FamilyName,"shrestha"),
                        new Claim(JwtClaimTypes.Email,"sudipshrestha960@gmail.com"),
                        new Claim(JwtClaimTypes.EmailVerified,"true",ClaimValueTypes.Boolean),
                        new Claim(JwtClaimTypes.PhoneNumber,"9861141726"),
                        new Claim(JwtClaimTypes.Role,"admin")
                    }
                },
                new TestUser
                {
                    SubjectId = "AA0EA8DF-F22B-4247-A07B-8F5940A748DF",
                    Username = "hello",
                    Password = "password",
                    Claims = new List<Claim>()
                    {
                        new Claim(JwtClaimTypes.Name, "Hello Shrestha"),
                        new Claim(JwtClaimTypes.GivenName,"hello"),
                        new Claim(JwtClaimTypes.FamilyName,"shrestha"),
                        new Claim(JwtClaimTypes.Email,"sudipshrestha960@gmail.com"),
                        new Claim(JwtClaimTypes.EmailVerified,"true",ClaimValueTypes.Boolean),
                        new Claim(JwtClaimTypes.PhoneNumber,"9861141726"),
                        new Claim(JwtClaimTypes.Role,"user")
                    }
                }
            };
    }
}