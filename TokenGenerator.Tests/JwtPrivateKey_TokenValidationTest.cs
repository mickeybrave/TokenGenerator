using ForceDotNetJwtCompanion;
using ForceDotNetJwtCompanion.Util;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Configuration.UserSecrets;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace TokenGenerator.Tests
{
    public class JwtPrivateKey_TokenValidationTest
    {
        private const string ServerKeyTrialAccountFileName = @"\MyTrialServer.key";
        private const string ServerKeySandBoxFileName = @"\MySandBoxServer.key";
        private const string AppDataFolderPath = @"\Microsoft\UserSecrets\";
        private readonly string _secretTrialKeyFilePath;
        private readonly string _secretSandBoxKeyFilePath;

        private readonly IConfiguration _config;
        public JwtPrivateKey_TokenValidationTest()
        {
            var builder = new ConfigurationBuilder()
             .AddUserSecrets<JwtPrivateKey_TokenValidationTest>();

            _config = builder.Build();

            var userSecretFolderGuidName = Assembly.GetExecutingAssembly()
                    .GetCustomAttribute<UserSecretsIdAttribute>()
                    .UserSecretsId;

            var secretsFolder =
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData)
                + AppDataFolderPath + userSecretFolderGuidName;

            _secretTrialKeyFilePath = secretsFolder + ServerKeyTrialAccountFileName;
            _secretSandBoxKeyFilePath = secretsFolder + ServerKeySandBoxFileName;
        }


        [Fact]
        public async Task Authenticate_Success_MyTestLogin_By_ClientId_Secret()
        {
            var apiVersion = "v50.0";
            var privateKey = CommonHelpers.LoadFromFile(_secretTrialKeyFilePath);
            var clientId = _config["CRM:Trial:ClientId"];
            var username = _config["CRM:Trial:User"];
            var clientSecret = _config["CRM:Trial:Secret"];


            var isProd = true;
            var authClient = new JwtAuthenticationClient(apiVersion, isProd);
            var redirectUri = "https://login.salesforce.com";
            var endpoint =
            $"https://login.salesforce.com/services/oauth2/token?response_type=token&client_id={clientId}&redirect_uri={redirectUri}";

            await authClient.JwtPrivateKeyAsync(
                            clientId,
                            privateKey,
                            clientSecret,
                            username,
                            endpoint);

            var accessToken = authClient.AccessToken;

            Assert.NotNull(accessToken);
        }

        [Fact]
        public async Task Authenticate_Success_MyTestLogin_Secret()
        {
            var apiVersion = "v50.0";
           
            var isProd = false;
            var privateKey = CommonHelpers.LoadFromFile(_secretTrialKeyFilePath);
            var clientId = _config["CRM:Trial:ClientId"];
            var username = _config["CRM:Trial:User"];
            var clientSecret = _config["CRM:Trial:Secret"];

            var authClient = new JwtAuthenticationClient(apiVersion, isProd);
            var redirectUri = "https://login.salesforce.com";
            var endpoint =
            $"https://login.salesforce.com/services/oauth2/token?response_type=token&client_id={clientId}&redirect_uri={redirectUri}";

            await authClient.JwtPrivateKeyAsync(
                            clientId,
                            privateKey,
                            clientSecret,
                            username,
                            endpoint);

            var accessToken = authClient.AccessToken;

            Assert.NotNull(accessToken);
        }

        [Fact]
        public async Task Authenticate_Success_MyTestLogin_ByClientId_Secret()
        {
            var apiVersion = "v50.0";
            var isProd = false;

            var privateKey = CommonHelpers.LoadFromFile(_secretTrialKeyFilePath);
            var clientId = _config["CRM:Trial:ClientId"];
            var username = _config["CRM:Trial:User"];
            var clientSecret = _config["CRM:Trial:Secret"];

            var authClient = new JwtAuthenticationClient(apiVersion, isProd);
            var endpoint =
            $"https://login.salesforce.com/services/oauth2/token";

            await authClient.JwtPrivateKeyByClientIdAsync(
                            clientId,
                            privateKey,
                            clientSecret,
                            username,
                            endpoint);

            var accessToken = authClient.AccessToken;

            Assert.NotNull(accessToken);
        }

      


        [Fact]
        public async Task Authenticate_Success_MyTestLogin()
        {
            var apiVersion = "v50.0";
            var isProd = true;
            var privateKey = CommonHelpers.LoadFromFile(_secretTrialKeyFilePath);
            var clientId = _config["CRM:Trial:ClientId"];
            var username = _config["CRM:Trial:User"];
            var clientSecret = _config["CRM:Trial:Secret"];

          
            var authClient = new JwtAuthenticationClient(apiVersion, isProd);
            var redirectUri = "https://login.salesforce.com";
            var endpoint =
            $"https://login.salesforce.com/services/oauth2/token?response_type=token&client_id={clientId}&redirect_uri={redirectUri}";

            await authClient.JwtPrivateKeyAsync(
                            clientId,
                            privateKey,
                            clientSecret,
                            username,
                            endpoint);

            var accessToken = authClient.AccessToken;

            Assert.NotNull(accessToken);
        }


        [Fact]
        public async Task Authenticate_Success_MyTest_SandBox_CP_Login()
        {
            var apiVersion = "v50.0";
            var privateKey = CommonHelpers.LoadFromFile(_secretSandBoxKeyFilePath);
            var clientId = _config["CRM:Sandbox:ClientId"];
            var username = _config["CRM:Sandbox:User"];
            var clientSecret = _config["CRM:Sandbox:Secret"];


            var isProd = false;
          
            var authClient = new JwtAuthenticationClient(apiVersion, isProd);
            var redirectUri = "https://test.salesforce.com";
            var endpoint =
            $"https://test.salesforce.com/services/oauth2/token?response_type=token&client_id={clientId}&redirect_uri={redirectUri}";

            await authClient.JwtPrivateKeyAsync(
                            clientId,
                            privateKey,
                            clientSecret,
                            username,
                            endpoint);

            var accessToken = authClient.AccessToken;

            Assert.NotNull(accessToken);
        }


        [Fact]
        public async Task Authenticate_Success_SandBox_ByClientId_Secret()
        {
            var apiVersion = "v50.0";
            var isProd = false;

            var privateKey = CommonHelpers.LoadFromFile(_secretSandBoxKeyFilePath);
            var clientId = _config["CRM:Sandbox:ClientId"];
            var username = _config["CRM:Sandbox:User"];
            var clientSecret = _config["CRM:Sandbox:Secret"];

            var authClient = new JwtAuthenticationClient(apiVersion, isProd);
            var endpoint =
            $"https://test.salesforce.com/services/oauth2/token";

            await authClient.JwtPrivateKeyByClientIdAsync(
                            clientId,
                            privateKey,
                            clientSecret,
                            username,
                            endpoint);

            var accessToken = authClient.AccessToken;

            Assert.NotNull(accessToken);
        }


    }
}
