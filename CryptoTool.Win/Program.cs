using System.Globalization;
using System.Text;

namespace CryptoTool.Win
{
    internal static class Program
    {
        /// <summary>
        ///  The main entry point for the application.
        /// </summary>
        [STAThread]
        static void Main()
        {
            try
            {
                // Set encoding to UTF-8 to handle Chinese characters properly
                Console.OutputEncoding = Encoding.UTF8;
                Console.InputEncoding = Encoding.UTF8;
                
                // Set the default encoding for the application
                Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
                
                // Ensure culture info supports Chinese characters
                Thread.CurrentThread.CurrentCulture = CultureInfo.InvariantCulture;
                Thread.CurrentThread.CurrentUICulture = CultureInfo.InvariantCulture;
                
                // Set application-wide culture
                CultureInfo.DefaultThreadCurrentCulture = CultureInfo.InvariantCulture;
                CultureInfo.DefaultThreadCurrentUICulture = CultureInfo.InvariantCulture;
            }
            catch
            {
                // Ignore if console encoding cannot be set in some environments
            }
            
            // Initialize application configuration
            ApplicationConfiguration.Initialize();
            
            // Run main form
            Application.Run(new MainForm());
        }
    }
}