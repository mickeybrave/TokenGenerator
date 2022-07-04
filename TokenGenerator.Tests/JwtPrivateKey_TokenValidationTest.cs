using ForceDotNetJwtCompanion;
using ForceDotNetJwtCompanion.Util;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace TokenGenerator.Tests
{
    public class JwtPrivateKey_TokenValidationTest
    {
        [Fact]
        public async Task Authenticate_Success_CP_TestLogin()
        {
            var apiVersion = "v50.0";
            var privateKey = CommonHelpers.LoadFromFile(@"C:\Users\brave\AppData\Roaming\Microsoft\UserSecrets\7312e39b-0ff9-46bd-a9c2-8e41c87df628/server.key");
            var passPhrase = "407958DBB32AC9B8DC1ED8F835365489CFEFA338AA27BED4A68A88E4CF6348DC";
            var isProd = true;
            var authClient = new JwtAuthenticationClient(apiVersion, isProd);
            var clientId = "3MVG9N6eDmZRVJOkDZH0OZB49slELDN0qfY20cVzZzKD4qzubrlLwNS9N0904KET6L2qhRFlyK.4FPUf7wuLA";
            var redirectUri = "https://login.salesforce.com";
            var username = "crmservicesf@countdown.co.nz.test";
            var endpoint =
            $"https://login.salesforce.com/services/oauth2/token?response_type=token&client_id={clientId}&redirect_uri={redirectUri}";

            await authClient.JwtPrivateKeyAsync(
                            clientId,
                            privateKey,
                            passPhrase,
                            username,
                            endpoint);

            var accessToken = authClient.AccessToken;
            Assert.NotNull(accessToken);
        }

        [Fact]
        public async Task Authenticate_Success_CP_TestLogin_ByClientId_Secret()
        {
            var apiVersion = "v50.0";
            var privateKey = CommonHelpers.LoadFromFile(@"C:\Users\brave\AppData\Roaming\Microsoft\UserSecrets\7312e39b-0ff9-46bd-a9c2-8e41c87df628/server.key");
            var passPhrase = "407958DBB32AC9B8DC1ED8F835365489CFEFA338AA27BED4A68A88E4CF6348DC";
            var isProd = true;
            var authClient = new JwtAuthenticationClient(apiVersion, isProd);
            var clientId = "3MVG9N6eDmZRVJOkDZH0OZB49slELDN0qfY20cVzZzKD4qzubrlLwNS9N0904KET6L2qhRFlyK.4FPUf7wuLA";
            var username = "crmservicesf@countdown.co.nz.test";
            var endpoint = $"https://login.salesforce.com/services/oauth2/token";


            await authClient.JwtPrivateKeyByClientIdAsync(
                            clientId,
                            privateKey,
                            passPhrase,
                            username,
                            endpoint);

            var accessToken = authClient.AccessToken;
            Assert.NotNull(accessToken);
        }

        [Fact]
        public async Task Authenticate_Success_CP_Login_By_ClientId_Secret()
        {
            var apiVersion = "v50.0";
            var privateKey = CommonHelpers.LoadFromFile(@"C:\Users\brave\AppData\Roaming\Microsoft\UserSecrets\7312e39b-0ff9-46bd-a9c2-8e41c87df628\server.key");
            var clientId = "3MVG9N6eDmZRVJOkDZH0OZB49srYoRFK.TOTv_hAW4tLq8l.p3yTo0NqMIRltFTH38nmI6hgThDvEV0XG8d0.";
            var passPhrase = "DB979B87530485840F0A6912EEEE1CFBF9FFBA6BABC9EE739E3359F6B63F4BF6";
            var isProd = false;

            var authClient = new JwtAuthenticationClient(apiVersion, isProd);
            var redirectUri = "https://login.salesforce.com";
            var endpoint =
            $"https://login.salesforce.com/services/oauth2/token?response_type=token&client_id={clientId}&redirect_uri={redirectUri}";

            await authClient.JwtPrivateKeyAsync(
                            clientId,
                            privateKey,
                            passPhrase,
                            "cdx@countdown.co.nz",
                            endpoint);

            var accessToken = authClient.AccessToken;

            Assert.NotNull(accessToken);
        }


        [Fact]
        public async Task Authenticate_Success_MyTestLogin_By_ClientId_Secret()
        {
            var apiVersion = "v50.0";
            var privateKey = CommonHelpers.LoadFromFile(@"C:\source\CP\CDX\cerficate\server.key");
            var passPhrase = "BA25102E470B1B7C236E20B6107E6A0E859CE1136941F46130A9AB4D9FFEDE0B";
            var isProd = true;
            var clientId = "3MVG9wt4IL4O5wvLvR05VQHBuKeE0MfmYyjQM6t4ECw7YysfW8_3up.AY17t23xZWSePTXOH_NYhkHf7nL5o.";
            var authClient = new JwtAuthenticationClient(apiVersion, isProd);
            var redirectUri = "https://login.salesforce.com";
            var endpoint =
            $"https://login.salesforce.com/services/oauth2/token?response_type=token&client_id={clientId}&redirect_uri={redirectUri}";

            await authClient.JwtPrivateKeyAsync(
                            clientId,
                            privateKey,
                            passPhrase,
                            "michael.braverman-kxq8@force.com",
                            endpoint);

            var accessToken = authClient.AccessToken;

            Assert.NotNull(accessToken);
        }

        [Fact]
        public async Task Authenticate_Success_MyTestLogin_Secret()
        {
            var apiVersion = "v50.0";
            var privateKey = CommonHelpers.LoadFromFile(@"C:\source\CP\CDX\cerficate\server.key");
            var passPhrase = "BA25102E470B1B7C236E20B6107E6A0E859CE1136941F46130A9AB4D9FFEDE0B";
            var isProd = false;
            var clientId = "3MVG9wt4IL4O5wvLvR05VQHBuKeE0MfmYyjQM6t4ECw7YysfW8_3up.AY17t23xZWSePTXOH_NYhkHf7nL5o.";
            var authClient = new JwtAuthenticationClient(apiVersion, isProd);
            var redirectUri = "https://login.salesforce.com";
            var endpoint =
            $"https://login.salesforce.com/services/oauth2/token?response_type=token&client_id={clientId}&redirect_uri={redirectUri}";

            await authClient.JwtPrivateKeyAsync(
                            clientId,
                            privateKey,
                            passPhrase,
                            "michael.braverman-kxq8@force.com",
                            endpoint);

            var accessToken = authClient.AccessToken;

            Assert.NotNull(accessToken);
        }

        [Fact]
        public async Task Authenticate_Success_MyTestLogin_ByClientId_Secret()
        {
            var apiVersion = "v50.0";
            var privateKey = CommonHelpers.LoadFromFile(@"C:\source\CP\CDX\cerficate\server.key");
            var passPhrase = "BA25102E470B1B7C236E20B6107E6A0E859CE1136941F46130A9AB4D9FFEDE0B";
            var isProd = false;
            var clientId = "3MVG9wt4IL4O5wvLvR05VQHBuKeE0MfmYyjQM6t4ECw7YysfW8_3up.AY17t23xZWSePTXOH_NYhkHf7nL5o.";
            var authClient = new JwtAuthenticationClient(apiVersion, isProd);
            var endpoint =
            $"https://login.salesforce.com/services/oauth2/token";

            await authClient.JwtPrivateKeyByClientIdAsync(
                            clientId,
                            privateKey,
                            passPhrase,
                            "michael.braverman-kxq8@force.com",
                            endpoint);

            var accessToken = authClient.AccessToken;

            Assert.NotNull(accessToken);
        }

      


        [Fact]
        public async Task Authenticate_Success_MyTestLogin()
        {
            var apiVersion = "v50.0";
            var privateKey = CommonHelpers.LoadFromFile(@"C:\source\CP\CDX\cerficate\server.key");
            var passPhrase = "BA25102E470B1B7C236E20B6107E6A0E859CE1136941F46130A9AB4D9FFEDE0B";
            var isProd = true;
            var clientId = "3MVG9wt4IL4O5wvLvR05VQHBuKeE0MfmYyjQM6t4ECw7YysfW8_3up.AY17t23xZWSePTXOH_NYhkHf7nL5o.";
            var authClient = new JwtAuthenticationClient(apiVersion, isProd);
            var redirectUri = "https://login.salesforce.com";
            var endpoint =
            $"https://login.salesforce.com/services/oauth2/token?response_type=token&client_id={clientId}&redirect_uri={redirectUri}";

            await authClient.JwtPrivateKeyAsync(
                            clientId,
                            privateKey,
                            passPhrase,
                            "michael.braverman-kxq8@force.com",
                            endpoint);

            var accessToken = authClient.AccessToken;

            Assert.NotNull(accessToken);
        }

      
    }
}
