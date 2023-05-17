using Microsoft.Identity.Client;
using Microsoft.Identity.Client.Broker;
using Microsoft.Identity.Client.Extensions.Msal;
using Microsoft.IdentityModel.Abstractions;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace sso
{
    public static class Settings
    {
        // Public Client setup
        public const string ClientId = "1d18b3b0-251b-4714-a02a-9956cec86c2d";
        public const string Authority = "https://login.microsoftonline.com/common"; // IMPORTANT: use /organizations for Work and School accounts only
        public static readonly string[] Scopes = new[] { "user.read" };

        // App registration setup
        // 1. Register http://localhost redirect URI (for system browser for Mac, Linux etc.)
        // 2. Register ms-appx-web://microsoft.aad.brokerplugin/{ClientId} (for WAM)

        // Token Caching setup - Windows
        private static readonly string s_cacheFilePath =
                   Path.Combine(MsalCacheHelper.UserRootDirectory, "msal.contoso.cache");
        public static readonly string CacheFileName = Path.GetFileName(s_cacheFilePath);
        public static readonly string CacheDir = Path.GetDirectoryName(s_cacheFilePath);

        // Token Caching setup - Mac
        public static readonly string KeyChainServiceName = "Contoso.MyProduct";
        public static readonly string KeyChainAccountName = "MSALCache";

        // Token Caching setup - Linux
        public static readonly string LinuxKeyRingSchema = "com.contoso.msaltokencache";
        public static readonly string LinuxKeyRingCollection = MsalCacheHelper.LinuxKeyRingDefaultCollection;
        public static readonly string LinuxKeyRingLabel = "MSAL token cache for Contoso.";
        public static readonly KeyValuePair<string, string> LinuxKeyRingAttr1 = new KeyValuePair<string, string>("Version", "1");
        public static readonly KeyValuePair<string, string> LinuxKeyRingAttr2 = new KeyValuePair<string, string>("ProductGroup", "Contoso");
    }

    internal class Program
    {
        private static IPublicClientApplication _pca = null;

        public async static Task Main(string[] args)
        {
            await InitializePublicClientAsync().ConfigureAwait(false);


            while (true)
            {
                Console.Clear();
                Console.ResetColor();

                // Tries to get a token silently from: cache, Windows, IWA. If it all fails, interactive.
                AuthenticationResult authenticationResult = await LoginSilentAndInteractiveAsync().ConfigureAwait(false);
                PrintSuccessResult(authenticationResult);

                // display menu
                Console.WriteLine(@$"                        
                        1. Change account - interactive via account picker 
                        2. Change account - by login hint (silent auth if login hint matches a Windows account)
                        3. (for test) - force sign-out
                           
                        x. Exit app

                    Enter your Selection: ");
                char.TryParse(Console.ReadLine(), out var selection);

                try
                {
                    switch (selection)
                    {
                        case '1': // If user does not like the default account, they can re-login interactively
                            await LogoutAsync().ConfigureAwait(false);
                            AuthenticationResult authenticationResult2 = await LoginInteractiveAsync().ConfigureAwait(false);

                            PrintSuccessResult(authenticationResult2);

                            break;

                        case '2': // If user does not like the default account, they can re-login and provide a login hint. WAM may be able to log-in silently.
                            await LogoutAsync().ConfigureAwait(false);

                            Console.WriteLine("Enter username: ");
                            string loginHint = Console.ReadLine();

                            AuthenticationResult authenticationResult3 = await LoginInteractiveAsync(loginHint).ConfigureAwait(false);
                            PrintSuccessResult(authenticationResult3);

                            break;

                        case '3':
                            await LogoutAsync().ConfigureAwait(false);
                            break;
                        case 'x':
                            Console.WriteLine("Exiting...");
                            await Task.Delay(1000);
                            return;
                    }

                    Console.WriteLine("\n\r\n\rPress any key to continue");
                    Console.ReadKey();

                }
                catch (Exception ex)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("An error occurred: " + ex);
                    Console.ResetColor();
                }

            }

        }

        private static async Task<AuthenticationResult> LoginInteractiveAsync(string loginHint = null)
        {
            // If the operating system has UI 
            if (_pca.IsUserInteractive())
            {
                return await _pca.AcquireTokenInteractive(Settings.Scopes)
                    .WithLoginHint(loginHint)
                    .WithParentActivityOrWindow(WindowsHelper.GetConsoleOrTerminalWindow())
                    .ExecuteAsync()
                    .ConfigureAwait(false);
            }

            // If the operating system does not have UI (e.g. SSH into Linux), you can fallback to device code, however this 
            // flow will not satisfy the "device is managed" CA policy. 
            return await _pca.AcquireTokenWithDeviceCode(Settings.Scopes, (dcr) =>
            {
                Console.WriteLine(dcr.Message);
                return Task.CompletedTask;
            }).ExecuteAsync().ConfigureAwait(false);

        }

        private static async Task LogoutAsync()
        {
            var accounts = await _pca.GetAccountsAsync().ConfigureAwait(false);
            foreach (var acc in accounts)
            {
                Console.WriteLine($"Removing account {acc.Username}");
                await _pca.RemoveAsync(acc).ConfigureAwait(false);
            }
        }

        private static void PrintSuccessResult(AuthenticationResult authenticationResult)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("Access token retrieved from: " + authenticationResult.AuthenticationResultMetadata.TokenSource);
            Console.WriteLine("Access token is for: " + authenticationResult.Account.Username);
            Console.ResetColor();
        }

        private static async Task<AuthenticationResult> LoginSilentAndInteractiveAsync()
        {
            var existingAccount = await FetchExistingAccountFromCache().ConfigureAwait(false);

            try
            {
                // 1. Try to sing-in the previously signed-in account
                if (existingAccount != null)
                {
                    Console.WriteLine("Found account in the cache - try to use it");

                    return await _pca.AcquireTokenSilent(
                        Settings.Scopes,
                        existingAccount)
                            .ExecuteAsync();
                }
                // 2. If it does not exist, try to sign in with the OS account. Only Windows broker supports this
                else
                {
                    Console.WriteLine("No accounts found in the cache. Trying Window's default account.");

                    return await _pca.AcquireTokenSilent(
                        Settings.Scopes,
                        PublicClientApplication.OperatingSystemAccount)
                            .ExecuteAsync();

                }
            }
            catch (MsalUiRequiredException ex)
            {
                Console.WriteLine("Could not acquire a token silently from cache or broker... " + ex);             
            }

            // 3. If all else fails, use interactive auth
            return await LoginInteractiveAsync(existingAccount?.Username).ConfigureAwait(false);
        }


        private static async Task<IAccount> FetchExistingAccountFromCache()
        {
            // get accounts from cache
            IEnumerable<IAccount> accounts = await _pca.GetAccountsAsync().ConfigureAwait(false);

            // Error corner case: we should always have 0 or 1 accounts, not expecting > 1
            // This is just an example of how to resolve this ambiguity, which can arise if more apps share a token cache.
            // Note that some apps prefer to use a random account from the cache.
            if (accounts.Count() > 1)
            {
                foreach (var acc in accounts)
                {
                    await _pca.RemoveAsync(acc);
                }
                return null;
            }

            return accounts.SingleOrDefault();
        }

        private static async Task InitializePublicClientAsync()
        {
            _pca = PublicClientApplicationBuilder
                            .Create(Settings.ClientId)
                            .WithAuthority(Settings.Authority)
                            .WithBroker(new BrokerOptions(BrokerOptions.OperatingSystems.Windows))
                            .WithRedirectUri("http://localhost") // Broker doesn't need this, but browser does (redirect uri is http://localhost - this needs to be registered)
                            .WithLogging(new Logger())
                            .Build();

            // token cache storage
            var storageProperties =
                 new StorageCreationPropertiesBuilder(Settings.CacheFileName, Settings.CacheDir)
                 .WithLinuxKeyring(
                     Settings.LinuxKeyRingSchema,
                     Settings.LinuxKeyRingCollection,
                     Settings.LinuxKeyRingLabel,
                     Settings.LinuxKeyRingAttr1,
                     Settings.LinuxKeyRingAttr2)
                 .WithMacKeyChain(
                     Settings.KeyChainServiceName,
                     Settings.KeyChainAccountName)
                 .Build();

            var cacheHelper = await MsalCacheHelper.CreateAsync(storageProperties);
            cacheHelper.RegisterCache(_pca.UserTokenCache);
        }       


    }

    public class Logger : IIdentityLogger
    {
        public Logger()
        {
            
        }
        public bool IsEnabled(EventLogLevel eventLogLevel)
        {
            return true;
        }

        public void Log(LogEntry entry)
        {
            File.AppendAllText(
                AppDomain.CurrentDomain.BaseDirectory + @"\logs.txt",
                entry.Message + "\n");
        }
    }

    public static class WindowsHelper
    {
        private enum GetAncestorFlags
        {
            GetParent = 1,
            GetRoot = 2,
            /// <summary>
            /// Retrieves the owned root window by walking the chain of parent and owner windows returned by GetParent.
            /// </summary>
            GetRootOwner = 3
        }

        /// <summary>
        /// Retrieves the handle to the ancestor of the specified window.
        /// </summary>
        /// <param name="hwnd">A handle to the window whose ancestor is to be retrieved.
        /// If this parameter is the desktop window, the function returns NULL. </param>
        /// <param name="flags">The ancestor to be retrieved.</param>
        /// <returns>The return value is the handle to the ancestor window.</returns>
        [DllImport("user32.dll", ExactSpelling = true)]
        private static extern IntPtr GetAncestor(IntPtr hwnd, GetAncestorFlags flags);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetConsoleWindow();

        public static IntPtr GetConsoleOrTerminalWindow()
        {
            IntPtr consoleHandle = GetConsoleWindow();
            IntPtr handle = GetAncestor(consoleHandle, GetAncestorFlags.GetRootOwner);

            return handle;
        }
    }
}
