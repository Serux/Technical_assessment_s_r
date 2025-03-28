using cli;
using Corvus.Json;
using System.CommandLine;
using System.Runtime.CompilerServices;
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
        urlOption.ArgumentHelpName = "BASEURL";

        var rootCommand = new RootCommand(
            $"Reads and parses a JSON file containing CVE vulnerabilities definitions and sends each to the API.{Environment.NewLine}{Environment.NewLine}" 
            +"If there is any problem parsing any vulnerability, a log containing the issue in created in the logs "
            +"folder and continues with next item in the file.");
        rootCommand.AddOption(fileOption);
        rootCommand.AddOption(urlOption);



        rootCommand.SetHandler(
            async (fileValue, urlValue) =>
                { 
                    // Validate URL by converting to URI
                    Uri? baseurl = null;
                    try
                    {
                        baseurl = new Uri(urlValue);
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

                    // Validates each item and sends it in an async way to the API.
                    List<Task> tasks = new List<Task>();
                    foreach (var item in schema.Value.Vulnerabilities)
                    {
                        var result = item.Validate(ValidationContext.ValidContext, ValidationLevel.Detailed);

                        if (!result.IsValid)
                        {
                            //TODO LOG VALIDATION ERRORS
                            foreach (ValidationResult error in result.Results)
                            {
                                Console.WriteLine(error);
                            }
                        }
                        else
                        {
                            //Launche each tasks as async and adds it to a list to await for every task to finish.
                            tasks.Add(PostVulnerability(baseurl, item));
                        }

                    }

                    //Awaits until all the tasks finish
                    await Task.WhenAll(tasks);

                    },
                    fileOption,
                    urlOption
        );

        return rootCommand.Invoke(args);
    }

    public static async Task PostVulnerability(Uri baseurl, VulnerabilitySchema.Vulnerability vuln)
    {
        var vulnJson = vuln.AsJsonElement.ToString();
        Console.WriteLine($"Sending {vuln.Title}");
        HttpClient client = new HttpClient();
        client.BaseAddress = baseurl;
        try
        {
            var response = await client.PostAsync("vulnerability", new StringContent(vulnJson, Encoding.UTF8, "application/json"));
            if (response != null)
            {
                Console.WriteLine(response.Content.ReadAsStringAsync().Result);
            }

        }
        catch (Exception e)
        {
            //TODO ERROR LOG if connection to server is not possible and other server errors.
            Console.WriteLine(e);
            throw;
        }
       
    }
}

