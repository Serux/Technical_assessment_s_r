using System.CommandLine;
using System.CommandLine.Invocation;


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
                    //Validate URL by converting to URI
                    Uri? url = null;
                    try
                    {
                        url = new Uri(urlValue);
                    }
                    catch (System.Exception e)
                    {
                        Console.WriteLine(e.Message);
                        System.Environment.Exit(1);
                    }

                    //Validate Path by checking if it exists and json extension
                    if(!Path.Exists(fileValue) || !Path.GetExtension(fileValue).Equals(".json", StringComparison.OrdinalIgnoreCase))
                    {
                        Console.WriteLine("File not valid.");
                        System.Environment.Exit(1);
                    }

                    // Application logic 
                    Console.WriteLine($"File: {fileValue}");
                    Console.WriteLine($"Url: {url}");
                },
                fileOption,
                urlOption
        );

        return rootCommand.Invoke(args);
    }
}
