using IdentityModel.Client;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace VTS.AuthServer.TestAPIClient
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Press Enter to run tests");
            Console.ReadLine();

            var program = new Program();

            var task = program.TestApiAsync();

            Console.WriteLine("Press Enter to run tests using password grant type");
            Console.ReadLine();

            task = program.TestApiOwnerPasswordAsync();

            Console.ReadLine();
        }

        private async Task TestApiAsync()
        {
            var disco = await DiscoverEndpointsAsync();
            if (disco != null)
            {
                var token = await RequestTokenAsync(disco.TokenEndpoint);
                if (token != null)
                {
                    await CallApiAsync(token.AccessToken);
                }
            }
        }

        private async Task TestApiOwnerPasswordAsync()
        {
            var disco = await DiscoverEndpointsAsync();
            if (disco != null)
            {
                var token = await RequestTokenAsync(disco.TokenEndpoint, "alice", "password");
                if (token != null)
                {
                    await CallApiAsync(token.AccessToken);
                }
            }
        }

        private async Task<DiscoveryResponse> DiscoverEndpointsAsync()
        {
            var disco = await DiscoveryClient.GetAsync("http://localhost:5000");
            if (disco.IsError)
            {
                Console.WriteLine(disco.Error);
                return null;
            }

            return disco;
        }

        private async Task<TokenResponse> RequestTokenAsync(string tokenEndpoint)
        {
            var tokenClient = new TokenClient(tokenEndpoint, "client", "secret");
            var tokenResponse = await tokenClient.RequestClientCredentialsAsync("api1");

            if (tokenResponse.IsError)
            {
                Console.WriteLine(tokenResponse.Error);
                return null;
            }

            Console.WriteLine(tokenResponse.Json);
            return tokenResponse;
        }

        private async Task<TokenResponse> RequestTokenAsync(string tokenEndpoint, string username, string password)
        {
            var tokenClient = new TokenClient(tokenEndpoint, "ro.client", "secret");
            var tokenResponse = await tokenClient.RequestResourceOwnerPasswordAsync(username, password, "api1");

            if (tokenResponse.IsError)
            {
                Console.WriteLine(tokenResponse.Error);
                return null;
            }

            Console.WriteLine(tokenResponse.Json);
            return tokenResponse;
        }

        private async Task CallApiAsync(string accessToken)
        {
            var client = new HttpClient();
            client.SetBearerToken(accessToken);

            var response = await client.GetAsync("http://localhost:5001/identity");
            if (!response.IsSuccessStatusCode)
            {
                Console.WriteLine(response.StatusCode);
            }
            else
            {
                var content = await response.Content.ReadAsStringAsync();
                Console.WriteLine(JArray.Parse(content));
            }

        }
    }
}
