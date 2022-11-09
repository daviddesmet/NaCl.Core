var target = Argument("Target", "Default");
var configuration =
    HasArgument("Configuration") ? Argument<string>("Configuration") :
    EnvironmentVariable("Configuration", "Release");

var artifactsDirectory = Directory("./Artifacts");

Task("Clean")
    .Description("Cleans the artifacts, bin and obj directories.")
    .Does(() =>
    {
        CleanDirectory(artifactsDirectory);
        DeleteDirectories(GetDirectories("**/bin"), new DeleteDirectorySettings() { Force = true, Recursive = true });
        DeleteDirectories(GetDirectories("**/obj"), new DeleteDirectorySettings() { Force = true, Recursive = true });
    });

Task("Restore")
    .Description("Restores NuGet packages.")
    .IsDependentOn("Clean")
    .Does(() =>
    {
        DotNetRestore();
    });

Task("Build")
    .Description("Builds the solution.")
    .IsDependentOn("Restore")
    .Does(() =>
    {
        DotNetBuild(
            ".",
            new DotNetBuildSettings()
            {
                Configuration = configuration,
                NoRestore = true,
            });
    });

Task("Test")
    .Description("Runs unit tests and outputs test results to the artifacts directory.")
    .DoesForEach(GetFiles("./test/**/*.Tests.csproj"), project =>
    {
        Information($"Preparing {project.GetFilename()} for test");
        var settings = new DotNetTestSettings()
        {
            Blame = true,
            Collectors = new string[] { "XPlat Code Coverage" },
            Configuration = configuration,
            Loggers = new string[]
            {
                $"trx;LogFileName={project.GetFilenameWithoutExtension()}.trx",
                $"html;LogFileName={project.GetFilenameWithoutExtension()}.html",
            },
            NoBuild = true,
            NoRestore = true,
            ResultsDirectory = $"{artifactsDirectory}/TestResults",
            Settings = "CodeCoverage.runsettings"
        };

        settings.EnvironmentVariables["COMPlus_EnableAVX2"] = "1";
        settings.EnvironmentVariables["COMPlus_EnableSSE3"] = "1";
        Information($"Running default {project.GetFilename()} test with SSE3 and AVX2 enabled");
        DotNetTest(project.ToString(), settings);

        settings.EnvironmentVariables["COMPlus_EnableAVX2"] = "0";
        settings.EnvironmentVariables["COMPlus_EnableSSE3"] = "1";
        Information($"Running {project.GetFilename()} test with SSE3 enabled and AVX2 disabled");
        DotNetTest(project.ToString(), settings);

        settings.EnvironmentVariables["COMPlus_EnableAVX2"] = "0";
        settings.EnvironmentVariables["COMPlus_EnableSSE3"] = "0";
        Information($"Running {project.GetFilename()} test with SSE3 and AVX2 disabled");
        DotNetTest(project.ToString(), settings);
    });

Task("CoverageReport")
    .IsDependentOn("Test")
    .Does(() =>
    {
        ReportGenerator(report: $"{artifactsDirectory}/TestResults/**/coverage.cobertura.xml",
                        targetDir: new DirectoryPath($"{artifactsDirectory}/TestResults/Coverage/Reports"),
                        settings: new ReportGeneratorSettings
                        {
                            ArgumentCustomization = args => args.Append("-reporttypes:HtmlInline;HTMLChart;Cobertura")
                        });
    });
        
Task("Pack")
    .Description("Creates the NuGet packages and outputs them to the artifacts directory.")
    .Does(() =>
    {
        DotNetPack(
            "./src/NaCl.Core/",
            new DotNetPackSettings()
            {
                Configuration = configuration,
                IncludeSymbols = false,
                MSBuildSettings = new DotNetMSBuildSettings()
                {
                    ContinuousIntegrationBuild = !BuildSystem.IsLocalBuild,
                },
                NoBuild = true,
                NoRestore = true,
                OutputDirectory = artifactsDirectory,
            });
    });

Task("Default")
    .Description("Cleans, restores, builds the solution, runs unit tests and then create the NuGet packages.")
    .IsDependentOn("Build")
    .IsDependentOn("Test")
    .IsDependentOn("Pack");

RunTarget(target);
