using System.Threading.Tasks;
using ForceDotNetJwtCompanion;
using ForceDotNetJwtCompanion.Util;
using Xunit;


namespace TokenGenerator.Tests
{
    public class AuthenticationClientTests : IClassFixture<SfMockAuthServerFixture>
    {
        private readonly SfMockAuthServerFixture _authServerFixture;
        public AuthenticationClientTests(SfMockAuthServerFixture authServerFixture)
        {
            _authServerFixture = authServerFixture;
        }

        [Fact]
        public async Task Authenticate_WithUnencryptedKey_Success()
        {
            var authClient = new JwtAuthenticationClient();
            await authClient.JwtUnencryptedPrivateKeyAsync(
                "jgasgdjasgdajsgdjs",
                CommonHelpers.LoadFromFile("TestKeys/server.key"),
                "user",
                $"http://localhost:{_authServerFixture.PublicPort}/services/oauth2/token"
                );
            Assert.Equal("jhjhdjashdjashdjashdjashdjasdhsjadhasjdhj", authClient.AccessToken);
            Assert.Equal("https://my-org.salesforce.com", authClient.InstanceUrl);
        }


        [Fact]
        public async Task Authenticate_CP_Success2()
        {
         
          

            var apiVersion = "v50.0";
            var privateKey = CommonHelpers.LoadFromFile(@"C:\Users\brave\AppData\Roaming\Microsoft\UserSecrets\7312e39b-0ff9-46bd-a9c2-8e41c87df628/server.key");
            var passPhrase = "your_secret_passphrase_loaded_from_somewhere";
            var isProd = false;
            var authClient = new JwtAuthenticationClient(apiVersion, isProd);

            await authClient.JwtPrivateKeyAsync(
                            "3MVG9N6eDmZRVJOkDZH0OZB49slELDN0qfY20cVzZzKD4qzubrlLwNS9N0904KET6L2qhRFlyK.4FPUf7wuLA",
                            privateKey,
                            passPhrase,
                            "sfsc-cdx@countdown.co.nz",
                            "https://test.salesforce.com/services/oauth2/token");

            var accessToken = authClient.AccessToken;

            Assert.Equal("jhjhdjashdjashdjashdjashdjasdhsjadhasjdhj", authClient.AccessToken);
            Assert.Equal("https://my-org.salesforce.com", authClient.InstanceUrl);
        }

        [Fact]
        public async Task Authenticate_CP_Success()
        {
            var authClient = new JwtAuthenticationClient();
            await authClient.JwtUnencryptedPrivateKeyAsync(
                "3MVG9N6eDmZRVJOkDZH0OZB49slELDN0qfY20cVzZzKD4qzubrlLwNS9N0904KET6L2qhRFlyK.4FPUf7wuLA",
                CommonHelpers.LoadFromFile(@"C:\Users\brave\AppData\Roaming\Microsoft\UserSecrets\7312e39b-0ff9-46bd-a9c2-8e41c87df628/server.key"),
                "crmservicesf@countdown.co.nz.test",
                $"https://test.salesforce.com/services/oauth2/token"
                );
            Assert.Equal("jhjhdjashdjashdjashdjashdjasdhsjadhasjdhj", authClient.AccessToken);
            Assert.Equal("https://my-org.salesforce.com", authClient.InstanceUrl);
        }

        [Fact]
        public async Task Authenticate_WithUnencryptedKey_401Exception()
        {
            var authClient = new JwtAuthenticationClient();
            var assertion = await Assert.ThrowsAsync<ForceAuthenticationException>(async () =>
            {
                await authClient.JwtUnencryptedPrivateKeyAsync(
                    "jgasgdjasgdajsgdjs",
                    CommonHelpers.LoadFromFile("TestKeys/server.key"),
                    "user-error",
                    $"http://localhost:{_authServerFixture.PublicPort}/services/oauth2/token"
                );
            });

            Assert.Equal("invalid_grant: an error description", assertion.Message);
        }

        [Fact]
        public async Task Authenticate_WithUnencryptedKey_404Exception()
        {
            var authClient = new JwtAuthenticationClient();
            var assertion = await Assert.ThrowsAsync<ForceAuthenticationException>(async () =>
            {
                await authClient.JwtUnencryptedPrivateKeyAsync(
                    "jgasgdjasgdajsgdjs",
                    CommonHelpers.LoadFromFile("TestKeys/server.key"),
                    "user",
                    $"http://localhost:{_authServerFixture.PublicPort}/servicesx/oauth2/token"
                );
            });

            // TODO Somewhat strange error in case of 404, needs further investigation
            Assert.Equal(
                "Unexpected character encountered while parsing value: <. Path '', line 0, position 0.",
                assertion.Message
                );
        }

    }
}
