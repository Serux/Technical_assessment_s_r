using cli;
using Corvus.Json;
using System.CommandLine;
using System.Text;
using System.Text.Json;


class Program
{
    static int Main(string[] args)
    {
        //Defining and linking cli options and usage info
        var fileOption = new Option<string>("--file", "Path to JSON file to process.") { IsRequired = true };
        fileOption.ArgumentHelpName = "FILEPATH";
        var urlOption = new Option<string>("--url", "URL to the CVE API where the JSON elements will be added.") { IsRequired = true };
        urlOption.ArgumentHelpName = "URL";

        var rootCommand = new RootCommand(
            $"Reads and parses a JSON file containing CVE vulnerabilities definitions and sends each to the API.{Environment.NewLine}{Environment.NewLine}" 
            +"If there is any problem parsing any vulnerability, a log containing the issue in created in the logs "
            +"folder and continues with next item in the file.");
        rootCommand.AddOption(fileOption);
        rootCommand.AddOption(urlOption);



        rootCommand.SetHandler(
            (fileValue, urlValue) =>
                { 
                    // Validate URL by converting to URI
                    Uri? url = null;
                    try
                    {
                        url = new Uri(urlValue);
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine(e.Message);
                        Environment.Exit(1);
                    }

                    // Validate Path by checking if it exists and json extension
                    if(!Path.Exists(fileValue) || !Path.GetExtension(fileValue).Equals(".json", StringComparison.OrdinalIgnoreCase))
                    {
                        Console.WriteLine("File not valid.");
                        Environment.Exit(1);
                    }

                    // Read File and parse into the schema (Without validating)
                    VulnerabilitySchema? schema = null;
                    try
                    {
                        using (Stream streamReader = new StreamReader(fileValue, Encoding.UTF8).BaseStream)
                        {
                            schema = VulnerabilitySchema.Parse(streamReader);
                        }
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine(e.Message);
                        Environment.Exit(1);
                    }

                    //TODO Go through all vulnerabilites, first validating them, logging if there is an issue and then posting them to the API
                    Console.WriteLine($"File: {schema.Value.Vulnerabilities[0].IsValid()}");
                    Console.WriteLine($"Url: {url}");
                    },
                    fileOption,
                    urlOption
        );

        return rootCommand.Invoke(args);
    }
}
