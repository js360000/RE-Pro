using System.Collections;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Resources;
using System.Text;
using System.Text.Json;
using ICSharpCode.BamlDecompiler;

var options = new JsonSerializerOptions
{
    PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
    WriteIndented = true,
};

if (args.Length == 3 && string.Equals(args[0], "extract-resources", StringComparison.OrdinalIgnoreCase))
{
    var assemblyPath = Path.GetFullPath(args[1]);
    var outputRoot = Path.GetFullPath(args[2]);
    Directory.CreateDirectory(outputRoot);

    var manifest = ManagedResourceExtractor.Extract(assemblyPath, outputRoot);
    await File.WriteAllTextAsync(
        Path.Combine(outputRoot, "resource_manifest.json"),
        JsonSerializer.Serialize(manifest, options),
        Encoding.UTF8
    );
    return 0;
}

if (args.Length == 4 && string.Equals(args[0], "decompile-baml", StringComparison.OrdinalIgnoreCase))
{
    var assemblyPath = Path.GetFullPath(args[1]);
    var jobsPath = Path.GetFullPath(args[2]);
    var outputRoot = Path.GetFullPath(args[3]);
    Directory.CreateDirectory(outputRoot);

    var jobs = JsonSerializer.Deserialize<BamlDecompileJobManifest>(
        await File.ReadAllTextAsync(jobsPath, Encoding.UTF8),
        options
    ) ?? new BamlDecompileJobManifest();
    var manifest = BamlXamlDecompiler.DecompileJobs(assemblyPath, jobs.Jobs, outputRoot);
    await File.WriteAllTextAsync(
        Path.Combine(outputRoot, "xaml_manifest.json"),
        JsonSerializer.Serialize(manifest, options),
        Encoding.UTF8
    );
    return 0;
}

Console.Error.WriteLine(
    "Usage:\n" +
    "  RePro.DotNetHelper extract-resources <assembly-path> <output-dir>\n" +
    "  RePro.DotNetHelper decompile-baml <assembly-path> <jobs-json> <output-dir>"
);
return 1;

static class BamlXamlDecompiler
{
    public static BamlXamlManifest DecompileJobs(
        string assemblyPath,
        IReadOnlyList<BamlDecompileJob> jobs,
        string outputRoot
    )
    {
        var manifest = new BamlXamlManifest
        {
            AssemblyPath = assemblyPath,
            OutputRoot = outputRoot,
        };
        var settings = new BamlDecompilerSettings
        {
            ThrowOnAssemblyResolveErrors = false,
        };
        var decompiler = new XamlDecompiler(assemblyPath, settings);

        foreach (var job in jobs)
        {
            var result = new BamlXamlResult
            {
                SourcePath = job.SourcePath,
                OutputRelativePath = SanitizeRelativePath(job.OutputRelativePath),
                SourceKind = job.SourceKind,
                ResourceName = job.ResourceName,
                EntryName = job.EntryName,
            };
            manifest.Results.Add(result);

            try
            {
                var sourcePath = Path.GetFullPath(job.SourcePath);
                if (!File.Exists(sourcePath))
                {
                    result.Error = "BAML source file was not found.";
                    continue;
                }

                using var stream = File.OpenRead(sourcePath);
                var xaml = decompiler.Decompile(stream);
                var relativePath = string.IsNullOrWhiteSpace(result.OutputRelativePath)
                    ? SanitizeRelativePath(Path.ChangeExtension(Path.GetFileName(sourcePath), ".xaml") ?? "view.xaml")
                    : result.OutputRelativePath;
                var destination = Path.Combine(outputRoot, relativePath);
                Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
                File.WriteAllText(destination, xaml.Xaml.ToString(), new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
                result.OutputPath = destination;
                result.OutputRelativePath = relativePath.Replace('\\', '/');
                result.TypeName = xaml.TypeName?.ToString();
                result.AssemblyReferences = xaml.AssemblyReferences;
                result.GeneratedMemberCount = xaml.GeneratedMembers.Count;
                result.Success = true;
                manifest.SuccessCount++;
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
            }
        }

        manifest.TotalJobs = jobs.Count;
        return manifest;
    }

    private static string SanitizeRelativePath(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "view.xaml";
        }

        var parts = value
            .Replace('\\', '/')
            .Split('/', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(part => part != "." && part != "..")
            .Select(part =>
            {
                var invalid = Path.GetInvalidFileNameChars();
                var cleaned = new string(part.Select(ch => invalid.Contains(ch) ? '_' : ch).ToArray()).TrimEnd('.', ' ');
                return string.IsNullOrWhiteSpace(cleaned) ? "item" : cleaned;
            });
        return string.Join(Path.DirectorySeparatorChar, parts);
    }
}

static class ManagedResourceExtractor
{
    public static AssemblyResourceManifest Extract(string assemblyPath, string outputRoot)
    {
        var manifest = new AssemblyResourceManifest
        {
            AssemblyPath = assemblyPath,
            ExtractionRoot = outputRoot,
        };

        using var stream = File.OpenRead(assemblyPath);
        using var peReader = new PEReader(stream);
        manifest.HasMetadata = peReader.HasMetadata;
        if (!peReader.HasMetadata)
        {
            return manifest;
        }

        var metadataReader = peReader.GetMetadataReader();
        manifest.IsAssembly = metadataReader.IsAssembly;
        var corHeader = peReader.PEHeaders.CorHeader;
        var resourcesDirectory = corHeader?.ResourcesDirectory ?? default;

        foreach (var handle in metadataReader.ManifestResources)
        {
            var resource = metadataReader.GetManifestResource(handle);
            var resourceManifest = new ManifestResourceEntry
            {
                Name = metadataReader.GetString(resource.Name),
                Visibility = resource.Attributes.ToString(),
                Offset = resource.Offset,
            };
            manifest.ManifestResources.Add(resourceManifest);

            if (!resource.Implementation.IsNil)
            {
                resourceManifest.ImplementationKind = resource.Implementation.Kind.ToString();
                resourceManifest.LinkedName = ResolveImplementationName(metadataReader, resource.Implementation);
                continue;
            }

            if (resourcesDirectory.RelativeVirtualAddress == 0 || resourcesDirectory.Size == 0)
            {
                resourceManifest.Error = "CLI resource directory was not present.";
                continue;
            }

            try
            {
                var payload = ReadEmbeddedResourcePayload(peReader, resourcesDirectory.RelativeVirtualAddress, resource.Offset);
                resourceManifest.Size = payload.Length;
                resourceManifest.RelativePath = WriteRawResource(outputRoot, resourceManifest.Name, payload);
                if (resourceManifest.Name.EndsWith(".resources", StringComparison.OrdinalIgnoreCase))
                {
                    resourceManifest.ResourceEntries = ExtractNestedResourceEntries(
                        payload,
                        outputRoot,
                        resourceManifest.Name
                    );
                }
            }
            catch (Exception ex)
            {
                resourceManifest.Error = ex.Message;
            }
        }

        return manifest;
    }

    private static byte[] ReadEmbeddedResourcePayload(PEReader peReader, int resourcesRva, long offset)
    {
        var section = peReader.GetSectionData(resourcesRva + checked((int)offset));
        var reader = section.GetReader();
        var length = reader.ReadInt32();
        return reader.ReadBytes(length);
    }

    private static string WriteRawResource(string outputRoot, string resourceName, byte[] payload)
    {
        var relativePath = SanitizeRelativePath(Path.Combine("manifest_resources", resourceName));
        var destination = Path.Combine(outputRoot, relativePath);
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        File.WriteAllBytes(destination, payload);
        return relativePath;
    }

    private static List<NestedResourceEntry> ExtractNestedResourceEntries(byte[] payload, string outputRoot, string resourceName)
    {
        var results = new List<NestedResourceEntry>();
        using var memory = new MemoryStream(payload, writable: false);
        using var reader = new ResourceReader(memory);
        var enumerator = reader.GetEnumerator();
        while (enumerator.MoveNext())
        {
            var entryName = Convert.ToString(enumerator.Key) ?? "resource";
            object? value;
            try
            {
                value = enumerator.Value;
            }
            catch (Exception ex)
            {
                results.Add(new NestedResourceEntry
                {
                    Name = entryName,
                    Category = "error",
                    Error = ex.Message,
                });
                continue;
            }

            var entry = WriteNestedResourceEntry(outputRoot, resourceName, entryName, value);
            results.Add(entry);
        }
        return results;
    }

    private static NestedResourceEntry WriteNestedResourceEntry(
        string outputRoot,
        string resourceName,
        string entryName,
        object? value
    )
    {
        var typeName = value?.GetType().FullName ?? "null";
        var baseRelative = Path.Combine(
            "resources",
            Path.GetFileNameWithoutExtension(resourceName),
            entryName.Replace('/', Path.DirectorySeparatorChar).Replace('\\', Path.DirectorySeparatorChar)
        );
        string category;
        byte[] payload;
        if (value is string text)
        {
            category = "text";
            payload = Encoding.UTF8.GetBytes(text);
        }
        else if (value is byte[] bytes)
        {
            category = "binary";
            payload = bytes;
        }
        else if (value is UnmanagedMemoryStream unmanaged)
        {
            category = "stream";
            using var temp = new MemoryStream();
            unmanaged.CopyTo(temp);
            payload = temp.ToArray();
        }
        else if (value is MemoryStream managedStream)
        {
            category = "stream";
            payload = managedStream.ToArray();
        }
        else if (value is Stream stream)
        {
            category = "stream";
            using var temp = new MemoryStream();
            stream.CopyTo(temp);
            payload = temp.ToArray();
        }
        else
        {
            category = "object";
            payload = Encoding.UTF8.GetBytes(value?.ToString() ?? string.Empty);
        }

        var probableBaml = entryName.EndsWith(".baml", StringComparison.OrdinalIgnoreCase) || LooksLikeBaml(payload);
        var relativePath = SanitizeRelativePath(baseRelative);
        if (Path.GetExtension(relativePath).Length == 0)
        {
            relativePath += probableBaml ? ".baml" : category == "text" ? ".txt" : ".bin";
        }

        var destination = Path.Combine(outputRoot, relativePath);
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        File.WriteAllBytes(destination, payload);
        return new NestedResourceEntry
        {
            Name = entryName,
            Category = category,
            ValueType = typeName,
            RelativePath = relativePath,
            Size = payload.LongLength,
            ProbableBaml = probableBaml,
            ProbableXamlPath = probableBaml
                ? Path.ChangeExtension(relativePath, ".xaml")?.Replace('\\', '/')
                : null,
        };
    }

    private static bool LooksLikeBaml(byte[] payload)
    {
        if (payload.Length == 0)
        {
            return false;
        }

        var ascii = Encoding.ASCII.GetBytes("MSBAML");
        if (payload.AsSpan().IndexOf(ascii) >= 0)
        {
            return true;
        }

        var unicode = Encoding.Unicode.GetBytes("MSBAML");
        return payload.AsSpan().IndexOf(unicode) >= 0;
    }

    private static string ResolveImplementationName(MetadataReader metadataReader, EntityHandle handle)
    {
        return handle.Kind switch
        {
            HandleKind.AssemblyReference => metadataReader.GetString(
                metadataReader.GetAssemblyReference((AssemblyReferenceHandle)handle).Name
            ),
            HandleKind.AssemblyFile => metadataReader.GetString(
                metadataReader.GetAssemblyFile((AssemblyFileHandle)handle).Name
            ),
            _ => handle.Kind.ToString(),
        };
    }

    private static string SanitizeRelativePath(string value)
    {
        var parts = value
            .Replace('\\', '/')
            .Split('/', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(part => part != "." && part != "..")
            .Select(part =>
            {
                var invalid = Path.GetInvalidFileNameChars();
                var cleaned = new string(part.Select(ch => invalid.Contains(ch) ? '_' : ch).ToArray()).TrimEnd('.', ' ');
                return string.IsNullOrWhiteSpace(cleaned) ? "item" : cleaned;
            });
        return string.Join(Path.DirectorySeparatorChar, parts);
    }
}

sealed class AssemblyResourceManifest
{
    public string AssemblyPath { get; set; } = string.Empty;

    public string ExtractionRoot { get; set; } = string.Empty;

    public bool HasMetadata { get; set; }

    public bool IsAssembly { get; set; }

    public List<ManifestResourceEntry> ManifestResources { get; } = new();
}

sealed class ManifestResourceEntry
{
    public string Name { get; set; } = string.Empty;

    public string Visibility { get; set; } = string.Empty;

    public long Offset { get; set; }

    public string? ImplementationKind { get; set; }

    public string? LinkedName { get; set; }

    public long Size { get; set; }

    public string? RelativePath { get; set; }

    public string? Error { get; set; }

    public List<NestedResourceEntry>? ResourceEntries { get; set; }
}

sealed class NestedResourceEntry
{
    public string Name { get; set; } = string.Empty;

    public string Category { get; set; } = string.Empty;

    public string? ValueType { get; set; }

    public string? RelativePath { get; set; }

    public long Size { get; set; }

    public bool ProbableBaml { get; set; }

    public string? ProbableXamlPath { get; set; }

    public string? Error { get; set; }
}

sealed class BamlDecompileJobManifest
{
    public List<BamlDecompileJob> Jobs { get; set; } = new();
}

sealed class BamlDecompileJob
{
    public string SourcePath { get; set; } = string.Empty;

    public string OutputRelativePath { get; set; } = string.Empty;

    public string? SourceKind { get; set; }

    public string? ResourceName { get; set; }

    public string? EntryName { get; set; }
}

sealed class BamlXamlManifest
{
    public string AssemblyPath { get; set; } = string.Empty;

    public string OutputRoot { get; set; } = string.Empty;

    public int TotalJobs { get; set; }

    public int SuccessCount { get; set; }

    public List<BamlXamlResult> Results { get; } = new();
}

sealed class BamlXamlResult
{
    public string SourcePath { get; set; } = string.Empty;

    public string OutputRelativePath { get; set; } = string.Empty;

    public string? OutputPath { get; set; }

    public string? SourceKind { get; set; }

    public string? ResourceName { get; set; }

    public string? EntryName { get; set; }

    public string? TypeName { get; set; }

    public List<string> AssemblyReferences { get; set; } = new();

    public int GeneratedMemberCount { get; set; }

    public bool Success { get; set; }

    public string? Error { get; set; }
}
