using cli;
using Corvus.Json;
using System.CommandLine;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Serilog;
using Serilog.Core;
using Serilog.Events;

class Program
{
    /// <summary>
    /// Logger for Information and Errors to Console, and Verbose to File.
    /// </summary>
    private static readonly ILogger<Program> _logger =
        LoggerFactory.Create(
            builder => builder.AddSerilog(
                new LoggerConfiguration()
                    .MinimumLevel.Verbose()
                    .WriteTo.Console(restrictedToMinimumLevel: LogEventLevel.Information)
                    .WriteTo.File("./logs/cli_.log", rollingInterval: RollingInterval.Day, restrictedToMinimumLevel: LogEventLevel.Verbose)
                    .CreateLogger()
            )
        ).CreateLogger<Program>();
    static int Main(string[] args)
    {
        //Configure logger

        _logger.LogInformation("Starting CLI...");

        //Defining and linking cli options and usage info
        var fileOption = new Option<string>("--file", "Path to JSON file to process.") { IsRequired = true };
        fileOption.ArgumentHelpName = "FILEPATH";
        var urlOption = new Option<string>("--url", "URL to the CVE API where the JSON elements will be added.") { IsRequired = true };
        urlOption.ArgumentHelpName = "BASEURL";

        var rootCommand = new RootCommand(
            $"Reads and parses a JSON file containing CVE vulnerabilities definitions and sends each to the API.{Environment.NewLine}{Environment.NewLine}"
            + "If there is any problem parsing any vulnerability, a log containing the issue in created in the logs "
            + "folder and continues with next item in the file.");
        rootCommand.AddOption(fileOption);
        rootCommand.AddOption(urlOption);



        rootCommand.SetHandler(
            async (fileValue, urlValue) =>
                {
                    // Validate URL by converting to URI
                    Uri? baseurl = null;
                    try
                    {
                        _logger.LogTrace($"Validating {urlValue}");
                        baseurl = new Uri(urlValue);

                    }
                    catch (Exception e)
                    {
                        _logger.LogError(e, "Failed to parse URL (http might be missing)");
                        Environment.Exit(1);
                    }

                    _logger.LogTrace($"Validating Path {fileValue}");
                    // Validate Path by checking if it exists and json extension
                    if (!Path.Exists(fileValue) || !Path.GetExtension(fileValue).Equals(".json", StringComparison.OrdinalIgnoreCase))
                    {
                        _logger.LogError("File not valid (File must be located in the folder ./files/ )");
                        Environment.Exit(1);
                    }

                    // Read File and parse into the schema.
                    //  All elements are parsed and can be validated afterwards.
                    VulnerabilitySchema? schema = null;
                    try
                    {
                        _logger.LogTrace($"Parsing file content into schema.");
                        using (Stream streamReader = new StreamReader(fileValue, Encoding.UTF8).BaseStream)
                        {
                            schema = VulnerabilitySchema.Parse(streamReader);
                        }
                    }
                    catch (Exception e)
                    {
                        _logger.LogError(e, "Failed to read and parse JSON file. (File content might be not valid JSON)");
                        Environment.Exit(1);
                    }

                    // Check for elements
                    if(schema.Value.Vulnerabilities.Count() == 0) 
                    {
                        _logger.LogInformation($"No vulnerabilities elements found in JSON file.");
                        Environment.Exit(1);
                    }

                    // Validates each item and sends it in an async way to the API.
                    List<Task> tasks = new List<Task>();
                    foreach (var item in schema.Value.Vulnerabilities)
                    {
                        _logger.LogTrace($"Validating element.");
                        var result = item.Validate(ValidationContext.ValidContext, ValidationLevel.Detailed);

                        if (!result.IsValid)
                        {
                            _logger.LogError($"Failed Validate JSON element: {item.AsJsonElement}");
                            _logger.LogError($"With Errors:");

                            foreach (ValidationResult error in result.Results)
                            {
                                _logger.LogError($"{error}");
                            }
                        }
                        else
                        {
                            _logger.LogTrace($"Valid Element: {item.CveValue}");
                            //Launch each tasks as async and adds it to a list to await for every task to finish.
                            tasks.Add(PostVulnerabilityAsync(baseurl, item));
                        }

                    }

                    //Awaits until all the tasks finish
                    await Task.WhenAll(tasks);
                    _logger.LogInformation($"All Tasks finished.");
                    Log.CloseAndFlush(); // Ensure logs are written
                },
                    fileOption,
                    urlOption
        );

        return rootCommand.Invoke(args);
    }

    /// <summary>
    /// Posts asyncronously a vulnerability object to the URL of the CVE API.
    /// </summary>
    /// <param name="baseurl">API URL</param>
    /// <param name="vuln">Vulnerability object</param>
    /// <returns></returns>
    public static async Task PostVulnerabilityAsync(Uri baseurl, VulnerabilitySchema.Vulnerability vuln)
    {
        //Convert vulnerability as Json for post content
        string vulnJson = vuln.AsJsonElement.ToString();

        HttpClient client = new HttpClient();
        client.BaseAddress = baseurl;
        try
        {

            _logger.LogInformation($"Sending {vuln.CveValue}.");
            var response = await client.PostAsync("vulnerability", new StringContent(vulnJson, Encoding.UTF8, "application/json"));
            if (response != null)
            {
                _logger.LogInformation($"Response: {response.Content.ReadAsStringAsync().Result}.");
            }

        }
        catch (Exception e)
        {
            _logger.LogError(e,$"Server error.");
            throw;
        }

    }
}

