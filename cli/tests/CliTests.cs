using NUnit.Framework;
using System.Diagnostics;

namespace CLITests
{
    [TestFixture]  // NUnit marker for test class
    public class CliTests
    {
        [Test]  // Marks a test method
        public void HelpCommand()
        {
            // Arrange
            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "dotnet",
                    Arguments = "/app/src/bin/Debug/net9.0/vulnerability-cli.dll --help",
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                }
            };

            // Act
            process.Start();
            
            string output = process.StandardOutput.ReadToEnd();
            process.WaitForExit();

            // Assert
            Assert.That(output, Does.Contain("Reads and parses a JSON file containing CVE vulnerabilities definitions and sends each to the API."));  // NUnit's fluent assertion

        }

    
    [Test]  // Marks a test method
        public void CommandFileNotValidParameter()
        {
            // Arrange
            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "dotnet",
                    Arguments = "/app/src/bin/Debug/net9.0/vulnerability-cli.dll --file a.json --url http://api:8000",
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                }
            };

            // Act
            process.Start();
            
            string output = process.StandardOutput.ReadToEnd();
            process.WaitForExit();

            // Assert
            Assert.That(output, Does.Contain("File not valid"));  // NUnit's fluent assertion

        }

        

    }
    
}