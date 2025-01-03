﻿// <auto-generated />
//
// To parse this JSON data, add NuGet 'Newtonsoft.Json' then do:
//
//    using fileHash;
//
//    var hash = Hash.FromJson(jsonString);



#nullable enable
#pragma warning disable CS8618
#pragma warning disable CS8601
#pragma warning disable CS8603

using System;
using System.Collections.Generic;

using System.Text.Json;
using System.Text.Json.Serialization;
using System.Globalization;

namespace fileHash;

public partial class Hash
{
    [JsonPropertyName("data")]
    public Data Data { get; set; }
}

public partial class Data
{
    [JsonPropertyName("id")]
    public string Id { get; set; }

    [JsonPropertyName("type")]
    public string Type { get; set; }

    [JsonPropertyName("links")]
    public Links Links { get; set; }

    [JsonPropertyName("attributes")]
    public Attributes Attributes { get; set; }
}

public partial class Attributes
{
    [JsonPropertyName("last_submission_date")]
    public long LastSubmissionDate { get; set; }

    [JsonPropertyName("pe_info")]
    public PeInfo PeInfo { get; set; }

    [JsonPropertyName("trid")]
    public Trid[] Trid { get; set; }

    [JsonPropertyName("detectiteasy")]
    public Detectiteasy Detectiteasy { get; set; }

    [JsonPropertyName("popular_threat_classification")]
    public PopularThreatClassification PopularThreatClassification { get; set; }

    [JsonPropertyName("vhash")]
    public string Vhash { get; set; }

    [JsonPropertyName("meaningful_name")]
    public string MeaningfulName { get; set; }

    [JsonPropertyName("signature_info")]
    public SignatureInfo SignatureInfo { get; set; }

    [JsonPropertyName("md5")]
    public string Md5 { get; set; }

    [JsonPropertyName("tlsh")]
    public string Tlsh { get; set; }

    [JsonPropertyName("ssdeep")]
    public string Ssdeep { get; set; }

    [JsonPropertyName("unique_sources")]
    public long UniqueSources { get; set; }

    [JsonPropertyName("magic")]
    public string Magic { get; set; }

    [JsonPropertyName("times_submitted")]
    public long TimesSubmitted { get; set; }

    [JsonPropertyName("last_analysis_date")]
    public long LastAnalysisDate { get; set; }

    [JsonPropertyName("type_tags")]
    public string[] TypeTags { get; set; }

    [JsonPropertyName("names")]
    public string[] Names { get; set; }

    [JsonPropertyName("sandbox_verdicts")]
    public SandboxVerdicts SandboxVerdicts { get; set; }

    [JsonPropertyName("last_analysis_stats")]
    public LastAnalysisStats LastAnalysisStats { get; set; }

    [JsonPropertyName("first_seen_itw_date")]
    public long FirstSeenItwDate { get; set; }

    [JsonPropertyName("reputation")]
    public long Reputation { get; set; }

    [JsonPropertyName("creation_date")]
    public long CreationDate { get; set; }

    [JsonPropertyName("first_submission_date")]
    public long FirstSubmissionDate { get; set; }

    [JsonPropertyName("type_extension")]
    public string TypeExtension { get; set; }

    [JsonPropertyName("total_votes")]
    public TotalVotes TotalVotes { get; set; }

    [JsonPropertyName("type_description")]
    public string TypeDescription { get; set; }

    [JsonPropertyName("tags")]
    public string[] Tags { get; set; }

    [JsonPropertyName("authentihash")]
    public string Authentihash { get; set; }

    [JsonPropertyName("last_modification_date")]
    public long LastModificationDate { get; set; }

    [JsonPropertyName("sha1")]
    public string Sha1 { get; set; }

    [JsonPropertyName("last_analysis_results")]
    public Dictionary<string, LastAnalysisResult> LastAnalysisResults { get; set; }

    [JsonPropertyName("size")]
    public long Size { get; set; }

    [JsonPropertyName("sha256")]
    public string Sha256 { get; set; }

    [JsonPropertyName("type_tag")]
    public string TypeTag { get; set; }

    [JsonPropertyName("crowdsourced_yara_results")]
    public CrowdsourcedYaraResult[] CrowdsourcedYaraResults { get; set; }

    [JsonPropertyName("magika")]
    public string Magika { get; set; }
}

public partial class CrowdsourcedYaraResult
{
    [JsonPropertyName("ruleset_id")]
    public string RulesetId { get; set; }

    [JsonPropertyName("rule_name")]
    public string RuleName { get; set; }

    [JsonPropertyName("ruleset_name")]
    public string RulesetName { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("description")]
    public string Description { get; set; }

    [JsonPropertyName("author")]
    public string Author { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("match_date")]
    public long? MatchDate { get; set; }

    [JsonPropertyName("source")]
    public Uri Source { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("match_in_subfile")]
    public bool? MatchInSubfile { get; set; }
}

public partial class Detectiteasy
{
    [JsonPropertyName("filetype")]
    public string Filetype { get; set; }

    [JsonPropertyName("values")]
    public Value[] Values { get; set; }
}

public partial class Value
{
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("info")]
    public string Info { get; set; }

    [JsonPropertyName("version")]
    public string Version { get; set; }

    [JsonPropertyName("type")]
    public string Type { get; set; }

    [JsonPropertyName("name")]
    public string Name { get; set; }
}

public partial class LastAnalysisResult
{
    [JsonPropertyName("method")]
    public string Method { get; set; }

    [JsonPropertyName("engine_name")]
    public string EngineName { get; set; }

    [JsonPropertyName("engine_version")]
    public string EngineVersion { get; set; }

    [JsonPropertyName("engine_update")]
    [JsonConverter(typeof(ParseStringConverter))]
    public long EngineUpdate { get; set; }

    [JsonPropertyName("category")]
    public string Category { get; set; }

    [JsonPropertyName("result")]
    public string Result { get; set; }
}

public partial class LastAnalysisStats
{
    [JsonPropertyName("malicious")]
    public long Malicious { get; set; }

    [JsonPropertyName("suspicious")]
    public long Suspicious { get; set; }

    [JsonPropertyName("undetected")]
    public long Undetected { get; set; }

    [JsonPropertyName("harmless")]
    public long Harmless { get; set; }

    [JsonPropertyName("timeout")]
    public long Timeout { get; set; }

    [JsonPropertyName("confirmed-timeout")]
    public long ConfirmedTimeout { get; set; }

    [JsonPropertyName("failure")]
    public long Failure { get; set; }

    [JsonPropertyName("type-unsupported")]
    public long TypeUnsupported { get; set; }
}

public partial class PeInfo
{
    [JsonPropertyName("timestamp")]
    public long Timestamp { get; set; }

    [JsonPropertyName("imphash")]
    public string Imphash { get; set; }

    [JsonPropertyName("machine_type")]
    public long MachineType { get; set; }

    [JsonPropertyName("entry_point")]
    public long EntryPoint { get; set; }

    [JsonPropertyName("resource_details")]
    public ResourceDetail[] ResourceDetails { get; set; }

    [JsonPropertyName("resource_langs")]
    public ResourceLangs ResourceLangs { get; set; }

    [JsonPropertyName("resource_types")]
    public ResourceTypes ResourceTypes { get; set; }

    [JsonPropertyName("sections")]
    public Section[] Sections { get; set; }

    [JsonPropertyName("compiler_product_versions")]
    public string[] CompilerProductVersions { get; set; }

    [JsonPropertyName("rich_pe_header_hash")]
    public string RichPeHeaderHash { get; set; }

    [JsonPropertyName("import_list")]
    public ImportList[] ImportList { get; set; }
}

public partial class ImportList
{
    [JsonPropertyName("library_name")]
    public string LibraryName { get; set; }

    [JsonPropertyName("imported_functions")]
    public string[] ImportedFunctions { get; set; }
}

public partial class ResourceDetail
{
    [JsonPropertyName("lang")]
    public string Lang { get; set; }

    [JsonPropertyName("chi2")]
    public double Chi2 { get; set; }

    [JsonPropertyName("filetype")]
    public string Filetype { get; set; }

    [JsonPropertyName("entropy")]
    public double Entropy { get; set; }

    [JsonPropertyName("sha256")]
    public string Sha256 { get; set; }

    [JsonPropertyName("type")]
    public string Type { get; set; }
}

public partial class ResourceLangs
{
    [JsonPropertyName("ENGLISH US")]
    public long EnglishUs { get; set; }
}

public partial class ResourceTypes
{
    [JsonPropertyName("RT_ICON")]
    public long RtIcon { get; set; }

    [JsonPropertyName("RT_VERSION")]
    public long RtVersion { get; set; }

    [JsonPropertyName("RT_GROUP_ICON")]
    public long RtGroupIcon { get; set; }
}

public partial class Section
{
    [JsonPropertyName("name")]
    public string Name { get; set; }

    [JsonPropertyName("chi2")]
    public double Chi2 { get; set; }

    [JsonPropertyName("virtual_address")]
    public long VirtualAddress { get; set; }

    [JsonPropertyName("entropy")]
    public double Entropy { get; set; }

    [JsonPropertyName("raw_size")]
    public long RawSize { get; set; }

    [JsonPropertyName("flags")]
    public string Flags { get; set; }

    [JsonPropertyName("virtual_size")]
    public long VirtualSize { get; set; }

    [JsonPropertyName("md5")]
    public string Md5 { get; set; }
}

public partial class PopularThreatClassification
{
    [JsonPropertyName("suggested_threat_label")]
    public string SuggestedThreatLabel { get; set; }

    [JsonPropertyName("popular_threat_name")]
    public PopularThreat[] PopularThreatName { get; set; }

    [JsonPropertyName("popular_threat_category")]
    public PopularThreat[] PopularThreatCategory { get; set; }
}

public partial class PopularThreat
{
    [JsonPropertyName("value")]
    public string Value { get; set; }

    [JsonPropertyName("count")]
    public long Count { get; set; }
}

public partial class SandboxVerdicts
{
    [JsonPropertyName("Zenbox")]
    public Box Zenbox { get; set; }

    [JsonPropertyName("CAPE Sandbox")]
    public Box CapeSandbox { get; set; }
}

public partial class Box
{
    [JsonPropertyName("category")]
    public string Category { get; set; }

    [JsonPropertyName("malware_classification")]
    public string[] MalwareClassification { get; set; }

    [JsonPropertyName("sandbox_name")]
    public string SandboxName { get; set; }

    [JsonPropertyName("malware_names")]
    public string[] MalwareNames { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("confidence")]
    public long? Confidence { get; set; }
}

public partial class SignatureInfo
{
    [JsonPropertyName("description")]
    public string Description { get; set; }

    [JsonPropertyName("file version")]
    public string FileVersion { get; set; }

    [JsonPropertyName("original name")]
    public string OriginalName { get; set; }

    [JsonPropertyName("product")]
    public string Product { get; set; }

    [JsonPropertyName("internal name")]
    public string InternalName { get; set; }

    [JsonPropertyName("copyright")]
    public string Copyright { get; set; }
}

public partial class TotalVotes
{
    [JsonPropertyName("harmless")]
    public long Harmless { get; set; }

    [JsonPropertyName("malicious")]
    public long Malicious { get; set; }
}

public partial class Trid
{
    [JsonPropertyName("file_type")]
    public string FileType { get; set; }

    [JsonPropertyName("probability")]
    public double Probability { get; set; }
}

public partial class Links
{
    [JsonPropertyName("self")]
    public Uri Self { get; set; }
}

public enum Category { Malicious, TypeUnsupported, Undetected };

public enum Method { Blacklist };

public partial class Hash
{
    public static Hash FromJson(string json) => JsonSerializer.Deserialize<Hash>(json, fileHash.Converter.Settings);
}

public static class Serialize
{
    public static string ToJson(this Hash self) => JsonSerializer.Serialize(self, fileHash.Converter.Settings);
}

internal static class Converter
{
    public static readonly JsonSerializerOptions Settings = new(JsonSerializerDefaults.General)
    {
        Converters =
            {
                CategoryConverter.Singleton,
                MethodConverter.Singleton,
                new DateOnlyConverter(),
                new TimeOnlyConverter(),
                IsoDateTimeOffsetConverter.Singleton
            },
    };
}

internal class CategoryConverter : JsonConverter<Category>
{
    public override bool CanConvert(Type t) => t == typeof(Category);

    public override Category Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var value = reader.GetString();
        switch (value)
        {
            case "malicious":
                return Category.Malicious;
            case "type-unsupported":
                return Category.TypeUnsupported;
            case "undetected":
                return Category.Undetected;
        }
        throw new Exception("Cannot unmarshal type Category");
    }

    public override void Write(Utf8JsonWriter writer, Category value, JsonSerializerOptions options)
    {
        switch (value)
        {
            case Category.Malicious:
                JsonSerializer.Serialize(writer, "malicious", options);
                return;
            case Category.TypeUnsupported:
                JsonSerializer.Serialize(writer, "type-unsupported", options);
                return;
            case Category.Undetected:
                JsonSerializer.Serialize(writer, "undetected", options);
                return;
        }
        throw new Exception("Cannot marshal type Category");
    }

    public static readonly CategoryConverter Singleton = new CategoryConverter();
}

internal class ParseStringConverter : JsonConverter<long>
{
    public override bool CanConvert(Type t) => t == typeof(long);

    public override long Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var value = reader.GetString();
        long l;
        if (Int64.TryParse(value, out l))
        {
            return l;
        }
        throw new Exception("Cannot unmarshal type long");
    }

    public override void Write(Utf8JsonWriter writer, long value, JsonSerializerOptions options)
    {
        JsonSerializer.Serialize(writer, value.ToString(), options);
        return;
    }

    public static readonly ParseStringConverter Singleton = new ParseStringConverter();
}

internal class MethodConverter : JsonConverter<Method>
{
    public override bool CanConvert(Type t) => t == typeof(Method);

    public override Method Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var value = reader.GetString();
        if (value == "blacklist")
        {
            return Method.Blacklist;
        }
        throw new Exception("Cannot unmarshal type Method");
    }

    public override void Write(Utf8JsonWriter writer, Method value, JsonSerializerOptions options)
    {
        if (value == Method.Blacklist)
        {
            JsonSerializer.Serialize(writer, "blacklist", options);
            return;
        }
        throw new Exception("Cannot marshal type Method");
    }

    public static readonly MethodConverter Singleton = new MethodConverter();
}

public class DateOnlyConverter : JsonConverter<DateOnly>
{
    private readonly string serializationFormat;
    public DateOnlyConverter() : this(null) { }

    public DateOnlyConverter(string? serializationFormat)
    {
        this.serializationFormat = serializationFormat ?? "yyyy-MM-dd";
    }

    public override DateOnly Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var value = reader.GetString();
        return DateOnly.Parse(value!);
    }

    public override void Write(Utf8JsonWriter writer, DateOnly value, JsonSerializerOptions options)
            => writer.WriteStringValue(value.ToString(serializationFormat));
}

public class TimeOnlyConverter : JsonConverter<TimeOnly>
{
    private readonly string serializationFormat;

    public TimeOnlyConverter() : this(null) { }

    public TimeOnlyConverter(string? serializationFormat)
    {
        this.serializationFormat = serializationFormat ?? "HH:mm:ss.fff";
    }

    public override TimeOnly Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var value = reader.GetString();
        return TimeOnly.Parse(value!);
    }

    public override void Write(Utf8JsonWriter writer, TimeOnly value, JsonSerializerOptions options)
            => writer.WriteStringValue(value.ToString(serializationFormat));
}

internal class IsoDateTimeOffsetConverter : JsonConverter<DateTimeOffset>
{
    public override bool CanConvert(Type t) => t == typeof(DateTimeOffset);

    private const string DefaultDateTimeFormat = "yyyy'-'MM'-'dd'T'HH':'mm':'ss.FFFFFFFK";

    private DateTimeStyles _dateTimeStyles = DateTimeStyles.RoundtripKind;
    private string? _dateTimeFormat;
    private CultureInfo? _culture;

    public DateTimeStyles DateTimeStyles
    {
        get => _dateTimeStyles;
        set => _dateTimeStyles = value;
    }

    public string? DateTimeFormat
    {
        get => _dateTimeFormat ?? string.Empty;
        set => _dateTimeFormat = (string.IsNullOrEmpty(value)) ? null : value;
    }

    public CultureInfo Culture
    {
        get => _culture ?? CultureInfo.CurrentCulture;
        set => _culture = value;
    }

    public override void Write(Utf8JsonWriter writer, DateTimeOffset value, JsonSerializerOptions options)
    {
        string text;


        if ((_dateTimeStyles & DateTimeStyles.AdjustToUniversal) == DateTimeStyles.AdjustToUniversal
                || (_dateTimeStyles & DateTimeStyles.AssumeUniversal) == DateTimeStyles.AssumeUniversal)
        {
            value = value.ToUniversalTime();
        }

        text = value.ToString(_dateTimeFormat ?? DefaultDateTimeFormat, Culture);

        writer.WriteStringValue(text);
    }

    public override DateTimeOffset Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        string? dateText = reader.GetString();

        if (string.IsNullOrEmpty(dateText) == false)
        {
            if (!string.IsNullOrEmpty(_dateTimeFormat))
            {
                return DateTimeOffset.ParseExact(dateText, _dateTimeFormat, Culture, _dateTimeStyles);
            }
            else
            {
                return DateTimeOffset.Parse(dateText, Culture, _dateTimeStyles);
            }
        }
        else
        {
            return default(DateTimeOffset);
        }
    }


    public static readonly IsoDateTimeOffsetConverter Singleton = new IsoDateTimeOffsetConverter();
}

#pragma warning restore CS8618
#pragma warning restore CS8601
#pragma warning restore CS8603
