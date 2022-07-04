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
        public async Task Authenticate_CP_Success1()
        {
            var apiVersion = "v50.0";
            var privateKey = CommonHelpers.LoadFromFile(@"C:\Users\brave\AppData\Roaming\Microsoft\UserSecrets\7312e39b-0ff9-46bd-a9c2-8e41c87df628/server.key");
            var passPhrase = "407958DBB32AC9B8DC1ED8F835365489CFEFA338AA27BED4A68A88E4CF6348DC";
            var isProd = false;
            var authClient = new JwtAuthenticationClient(apiVersion, isProd);
            var clientId = "3MVG9N6eDmZRVJOkDZH0OZB49slELDN0qfY20cVzZzKD4qzubrlLwNS9N0904KET6L2qhRFlyK.4FPUf7wuLA";
            var redirectUri = "https://login.salesforce.com";
            var endpoint =
            $"https://login.salesforce.com/services/oauth2/authorize?response_type=token&client_id={clientId}&redirect_uri={redirectUri}";

            await authClient.JwtPrivateKeyAsync(
                            clientId,
                            privateKey,
                            passPhrase,
                            "crmservicesf@countdown.co.nz.test",
                            endpoint);

            var accessToken = authClient.AccessToken;

            Assert.Equal("jhjhdjashdjashdjashdjashdjasdhsjadhasjdhj", authClient.AccessToken);
            Assert.Equal("https://my-org.salesforce.com", authClient.InstanceUrl);
        }
        [Fact]
        public async Task Authenticate_CP_Success2()
        {
            var apiVersion = "v50.0";
            var privateKey = CommonHelpers.LoadFromFile(@"C:\Users\brave\AppData\Roaming\Microsoft\UserSecrets\7312e39b-0ff9-46bd-a9c2-8e41c87df628/server.key");
            var clientId = "3MVG9N6eDmZRVJOkDZH0OZB49srYoRFK.TOTv_hAW4tLq8l.p3yTo0NqMIRltFTH38nmI6hgThDvEV0XG8d0.";
            var passPhrase = "DB979B87530485840F0A6912EEEE1CFBF9FFBA6BABC9EE739E3359F6B63F4BF6";
            var isProd = false;
            var authClient = new JwtAuthenticationClient(apiVersion, isProd);
            
            var redirectUri = "https://login.salesforce.com";
            var endpoint =
            $"https://login.salesforce.com/services/oauth2/authorize?response_type=token&client_id={clientId}&redirect_uri={redirectUri}";

            await authClient.JwtPrivateKeyAsync(
                            clientId,
                            privateKey,
                            passPhrase,
                            "crmservicesf@countdown.co.nz",
                            endpoint);

            var accessToken = authClient.AccessToken;

            Assert.Equal("jhjhdjashdjashdjashdjashdjasdhsjadhasjdhj", authClient.AccessToken);
            Assert.Equal("https://my-org.salesforce.com", authClient.InstanceUrl);
        }
        

        [Fact]
        public async Task Authenticate_CP_Success3()
        {



            var apiVersion = "v50.0";
            var privateKey = CommonHelpers.LoadFromFile(@"C:\source\CP\CDX\cerficate\server.key");
            var passPhrase = "BA25102E470B1B7C236E20B6107E6A0E859CE1136941F46130A9AB4D9FFEDE0B";
            var isProd = false;
            var clientId = "3MVG9wt4IL4O5wvLvR05VQHBuKeE0MfmYyjQM6t4ECw7YysfW8_3up.AY17t23xZWSePTXOH_NYhkHf7nL5o.";
            var authClient = new JwtAuthenticationClient(apiVersion, isProd);
            var redirectUri = "https://login.salesforce.com";
            var endpoint =
            $"https://login.salesforce.com/services/oauth2/authorize?response_type=token&client_id={clientId}&redirect_uri={redirectUri}";

            await authClient.JwtPrivateKeyAsync(
                            clientId,
                            privateKey,
                            passPhrase,
                            "michael.braverman-kxq8@force.com",
                            endpoint);

            var accessToken = authClient.AccessToken;

            Assert.Equal("jhjhdjashdjashdjashdjashdjasdhsjadhasjdhj", authClient.AccessToken);
            Assert.Equal("https://my-org.salesforce.com", authClient.InstanceUrl);
        }

        [Fact]
        public async Task Authenticate_CP_Success()
        {
           

            var apiVersion = "v50.0";
            var privateKey = @"C:\source\CP\CDX\cerficate\server.key";
            var passPhrase = "P@ssw0rd";
            var isProd = false;
            var authClient = new JwtAuthenticationClient(apiVersion, isProd);

            await authClient.JwtPrivateKeyAsync(
                            "3MVG9wt4IL4O5wvLvR05VQHBuKeE0MfmYyjQM6t4ECw7YysfW8_3up.AY17t23xZWSePTXOH_NYhkHf7nL5o.",
                            privateKey,
                            passPhrase,
                            "michael.braverman-kxq8@force.com",
                            "https://login.salesforce.com/services/oauth2/token"
                            );
            var accessToken = authClient.AccessToken;
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
