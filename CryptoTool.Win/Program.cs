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
                // Set console encoding to UTF-8 to handle Chinese characters
                Console.OutputEncoding = Encoding.UTF8;
                Console.InputEncoding = Encoding.UTF8;
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