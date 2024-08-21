using System.Net.Http.Headers;
using System.Runtime.InteropServices;

namespace Simpel {
    internal static class Program {
        /// <summary>
        ///  The main entry point for the application.
        /// </summary>
        [STAThread]

        [DllImport("kernel32")]
        private static extern bool AllocConsole();

        static void Main() {
            // To customize application configuration such as set high DPI settings or default font,
            // see https://aka.ms/applicationconfiguration.
            ApplicationConfiguration.Initialize();
            Application.Run(new Form1());
            
            
        }

        
    }
}