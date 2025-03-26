using System.CommandLine;
using System.CommandLine.Invocation;


class Program
{
    static int Main(string[] args)
    {
        //Defining and linking cli options
        var fileOption = new Option<string>("--file", "Path to json file") { IsRequired = true };
        var urlOption = new Option<string>("--url", "Url to CVE API") { IsRequired = true };

        var rootCommand = new RootCommand();
        rootCommand.AddOption(fileOption);
        rootCommand.AddOption(urlOption);



        rootCommand.SetHandler(
            (fileValue, urlValue) =>
                {
                    // Your application logic goes here
                    Console.WriteLine($"File: {fileValue}");
                    Console.WriteLine($"Url: {urlValue}");
                },
                fileOption,
                urlOption
        );

        return rootCommand.Invoke(args);
    }
}
