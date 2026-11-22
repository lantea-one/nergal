using System.Buffers;
using System.Globalization;
using System.Text.Json;
using Nergal.Core.Deployment;
using Nergal.Core.Policy;

namespace Nergal.Core.Agent;

/// <summary>Pure version-1 UTF-8 JSON codec for typed agent control requests and replies.</summary>
public static class AgentControlCodec
{
    /// <summary>Maximum control payload size in UTF-8 bytes (256 KiB).</summary>
    public const int MaximumPayloadLength = 262_144;

    /// <summary>Maximum number of rules allowed in one control request.</summary>
    public const int MaximumRuleCount = 4096;

    /// <summary>Encodes a validated control request into a UTF-8 JSON payload.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="request"/> is null.</exception>
    public static byte[] EncodeRequest(AgentControlRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        var buffer = new ArrayBufferWriter<byte>();
        using var writer = new Utf8JsonWriter(buffer);
        writer.WriteStartObject();
        writer.WriteNumber("schemaVersion", 1);
        writer.WriteString("command", CommandName(request.Command));
        if (request.OperationId is { } opId)
        {
            writer.WriteString("operationId", opId.ToString("D"));
        }

        if (request.WatchdogId is { } watchdogId)
        {
            writer.WriteString("watchdogId", watchdogId.ToString("D"));
        }

        if (request.ConfirmationTimeoutSeconds is { } timeoutSeconds)
        {
            writer.WriteNumber("confirmationTimeoutSeconds", timeoutSeconds);
        }

        if (request.Bundle is { } bundle &&
            (bundle.Nat is not null || bundle.Bridge is not null || bundle.SchemaVersion != FirewallPolicyBundle.CurrentSchemaVersion))
        {
            writer.WritePropertyName("bundle");
            PolicyBundleJsonCodec.WriteBundle(writer, bundle);
        }
        else if (request.Policy is { } policy)
        {
            writer.WritePropertyName("policy");
            PolicyBundleJsonCodec.WriteFilterPolicy(writer, policy);
        }

        writer.WriteEndObject();
        writer.Flush();
        return buffer.WrittenSpan.ToArray();
    }

    /// <summary>Validates and decodes a control request without invoking any side effects.</summary>
    public static ControlRequestResult DecodeRequest(ReadOnlySpan<byte> payload)
    {
        if (payload.Length > MaximumPayloadLength)
        {
            return new(null, "payload.tooLarge");
        }

        try
        {
            using var document = JsonDocument.Parse(payload.ToArray(), new JsonDocumentOptions { MaxDepth = 12 });
            var root = document.RootElement;
            if (Duplicates(root))
            {
                return new(null, "request.duplicateProperty");
            }

            if (root.ValueKind != JsonValueKind.Object ||
                !root.TryGetProperty("schemaVersion", out var versionElement) ||
                versionElement.ValueKind != JsonValueKind.Number ||
                !versionElement.TryGetInt32(out var schemaVersion) || schemaVersion != 1 ||
                !root.TryGetProperty("command", out var commandElement) ||
                commandElement.ValueKind != JsonValueKind.String)
            {
                return new(null, "request.fields");
            }

            var command = ParseCommand(commandElement.GetString());
            if (command is null)
            {
                return new(null, "request.command");
            }

            if (command == AgentControlCommand.Status)
            {
                if (!Properties(root, "schemaVersion", "command"))
                {
                    return new(null, "request.fields");
                }

                return new(new AgentControlRequest(AgentControlCommand.Status), null);
            }

            if (command == AgentControlCommand.PrepareApply)
            {
                var hasWatchdog = root.TryGetProperty("watchdogId", out _);
                var hasPolicy = root.TryGetProperty("policy", out var policyEl);
                var hasBundle = root.TryGetProperty("bundle", out var bundleEl);
                if (hasPolicy == hasBundle)
                {
                    return new(null, "request.fields");
                }

                var payloadField = hasBundle ? "bundle" : "policy";
                var validProps = hasWatchdog
                    ? Properties(root, "schemaVersion", "command", "operationId", "watchdogId", "confirmationTimeoutSeconds", payloadField)
                    : Properties(root, "schemaVersion", "command", "operationId", "confirmationTimeoutSeconds", payloadField);
                if (!validProps)
                {
                    return new(null, "request.fields");
                }

                if (!TryParseGuid(root.GetProperty("operationId"), out var opId))
                {
                    return new(null, "request.operationId");
                }

                Guid? wdId = null;
                if (hasWatchdog)
                {
                    if (!TryParseGuid(root.GetProperty("watchdogId"), out var parsedWd))
                    {
                        return new(null, "request.watchdogId");
                    }

                    wdId = parsedWd;
                }

                var timeoutElement = root.GetProperty("confirmationTimeoutSeconds");
                if (timeoutElement.ValueKind != JsonValueKind.Number || !timeoutElement.TryGetInt32(out var timeout) || timeout is < 1 or > 3600)
                {
                    return new(null, "request.timeout");
                }

                if (hasBundle)
                {
                    var decodedBundle = PolicyBundleJsonCodec.TryParseBundleElement(bundleEl);
                    if (!decodedBundle.IsSuccess || decodedBundle.Value is null)
                    {
                        return new(null, "request.policy");
                    }

                    return new(new AgentControlRequest(AgentControlCommand.PrepareApply, opId, wdId, timeout, bundle: decodedBundle.Value), null);
                }

                var decodedFilter = PolicyBundleJsonCodec.TryParseFilterElement(policyEl);
                if (!decodedFilter.IsSuccess || decodedFilter.Value is null)
                {
                    return new(null, "request.policy");
                }

                return new(new AgentControlRequest(AgentControlCommand.PrepareApply, opId, wdId, timeout, decodedFilter.Value), null);
            }

            // Confirm / Rollback
            if (!Properties(root, "schemaVersion", "command", "operationId", "watchdogId"))
            {
                return new(null, "request.fields");
            }

            if (!TryParseGuid(root.GetProperty("operationId"), out var confirmOp))
            {
                return new(null, "request.operationId");
            }

            if (!TryParseGuid(root.GetProperty("watchdogId"), out var confirmWd))
            {
                return new(null, "request.watchdogId");
            }

            return new(new AgentControlRequest(command.Value, confirmOp, confirmWd), null);
        }
        catch (Exception err) when (err is JsonException or InvalidOperationException or ArgumentException)
        {
            return new(null, "request.invalidJson");
        }
    }

    /// <summary>Encodes a typed control reply into a bounded UTF-8 JSON payload.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="reply"/> is null.</exception>
    public static byte[] EncodeReply(AgentControlReply reply)
    {
        ArgumentNullException.ThrowIfNull(reply);
        var buffer = new ArrayBufferWriter<byte>();
        using var writer = new Utf8JsonWriter(buffer);
        writer.WriteStartObject();
        writer.WriteNumber("schemaVersion", 1);
        writer.WriteString("outcome", OutcomeName(reply.Outcome));
        if (reply.Revision is { } rev)
        {
            writer.WriteString("revision", rev.ToString(CultureInfo.InvariantCulture));
        }

        if (reply.OperationId is { } opId)
        {
            writer.WriteString("operationId", opId.ToString("D"));
        }

        if (reply.WatchdogId is { } wdId)
        {
            writer.WriteString("watchdogId", wdId.ToString("D"));
        }

        if (reply.ActivePhase is { } phase)
        {
            writer.WriteString("activePhase", PhaseName(phase));
        }

        if (reply.RemainingSeconds is { } rem)
        {
            writer.WriteNumber("remainingSeconds", rem);
        }

        if (reply.CandidateDigest is { } digest)
        {
            writer.WriteString("candidateDigest", digest);
        }

        if (reply.ErrorCode is { } err)
        {
            writer.WriteString("errorCode", err);
        }

        writer.WriteEndObject();
        writer.Flush();
        return buffer.WrittenSpan.ToArray();
    }

    /// <summary>Decodes a typed control reply while rejecting unknown properties, duplicate keys, or invalid metadata.</summary>
    public static ControlReplyResult DecodeReply(ReadOnlySpan<byte> payload)
    {
        if (payload.Length > MaximumPayloadLength)
        {
            return new(null, "payload.tooLarge");
        }

        try
        {
            using var document = JsonDocument.Parse(payload.ToArray(), new JsonDocumentOptions { MaxDepth = 8 });
            var root = document.RootElement;
            if (Duplicates(root))
            {
                return new(null, "reply.duplicateProperty");
            }

            if (root.ValueKind != JsonValueKind.Object ||
                !root.TryGetProperty("schemaVersion", out var ver) ||
                ver.ValueKind != JsonValueKind.Number || !ver.TryGetInt32(out var version) || version != 1 ||
                !root.TryGetProperty("outcome", out var outEl) || outEl.ValueKind != JsonValueKind.String)
            {
                return new(null, "reply.fields");
            }

            var allowed = new HashSet<string>(
                ["schemaVersion", "outcome", "revision", "operationId", "watchdogId", "activePhase", "remainingSeconds", "candidateDigest", "errorCode"],
                StringComparer.Ordinal);
            foreach (var prop in root.EnumerateObject())
            {
                if (!allowed.Contains(prop.Name))
                {
                    return new(null, "reply.fields");
                }
            }

            var outcome = ParseOutcome(outEl.GetString());
            if (outcome is null)
            {
                return new(null, "reply.outcome");
            }

            ulong? revision = null;
            if (root.TryGetProperty("revision", out var revEl))
            {
                if (revEl.ValueKind != JsonValueKind.String ||
                    !ulong.TryParse(revEl.GetString(), NumberStyles.None, CultureInfo.InvariantCulture, out var parsed) ||
                    parsed == 0 ||
                    parsed.ToString(CultureInfo.InvariantCulture) != revEl.GetString())
                {
                    return new(null, "reply.revision");
                }

                revision = parsed;
            }

            Guid? opId = null;
            if (root.TryGetProperty("operationId", out var opEl))
            {
                if (!TryParseGuid(opEl, out var parsedOp)) { return new(null, "reply.operationId"); }
                opId = parsedOp;
            }

            Guid? wdId = null;
            if (root.TryGetProperty("watchdogId", out var wdEl))
            {
                if (!TryParseGuid(wdEl, out var parsedWd)) { return new(null, "reply.watchdogId"); }
                wdId = parsedWd;
            }

            ApplyPhase? phase = null;
            if (root.TryGetProperty("activePhase", out var phEl))
            {
                if (phEl.ValueKind != JsonValueKind.String || ParsePhase(phEl.GetString()) is not { } p)
                {
                    return new(null, "reply.phase");
                }

                phase = p;
            }

            int? remaining = null;
            if (root.TryGetProperty("remainingSeconds", out var remEl))
            {
                if (remEl.ValueKind != JsonValueKind.Number || !remEl.TryGetInt32(out var parsedRem) || parsedRem is < 0 or > 3600)
                {
                    return new(null, "reply.remainingSeconds");
                }

                remaining = parsedRem;
            }

            string? digest = null;
            if (root.TryGetProperty("candidateDigest", out var digEl))
            {
                if (digEl.ValueKind != JsonValueKind.String) { return new(null, "reply.digest"); }
                var text = digEl.GetString();
                if (text is null || !AgentControlReply.IsHexSha256(text)) { return new(null, "reply.digest"); }
                digest = text;
            }

            string? errorCode = null;
            if (root.TryGetProperty("errorCode", out var errEl))
            {
                if (errEl.ValueKind != JsonValueKind.String) { return new(null, "reply.errorCode"); }
                var text = errEl.GetString();
                if (text is null || !AgentControlReply.IsSafeCode(text)) { return new(null, "reply.errorCode"); }
                errorCode = text;
            }

            if (outcome.Value is AgentControlOutcome.Denied or AgentControlOutcome.InvalidRequest &&
                (revision.HasValue || opId.HasValue || wdId.HasValue || phase.HasValue ||
                 remaining.HasValue || digest is not null || errorCode is not null))
            {
                return new(null, "reply.fields");
            }

            return new(new AgentControlReply(outcome.Value, revision, opId, wdId, phase, remaining, digest, errorCode), null);
        }
        catch (Exception err) when (err is JsonException or InvalidOperationException or ArgumentException)
        {
            return new(null, "reply.invalidJson");
        }
    }

    private static bool TryParseGuid(JsonElement el, out Guid id)
    {
        id = Guid.Empty;
        return el.ValueKind == JsonValueKind.String && Guid.TryParseExact(el.GetString(), "D", out id) && id != Guid.Empty;
    }

    private static string CommandName(AgentControlCommand cmd) => cmd switch
    {
        AgentControlCommand.Status => "status",
        AgentControlCommand.PrepareApply => "prepare-apply",
        AgentControlCommand.Confirm => "confirm",
        AgentControlCommand.Rollback => "rollback",
        _ => throw new ArgumentOutOfRangeException(nameof(cmd)),
    };

    private static AgentControlCommand? ParseCommand(string? name) => name switch
    {
        "status" => AgentControlCommand.Status,
        "prepare-apply" => AgentControlCommand.PrepareApply,
        "confirm" => AgentControlCommand.Confirm,
        "rollback" => AgentControlCommand.Rollback,
        _ => null,
    };

    private static string OutcomeName(AgentControlOutcome outcome) => outcome switch
    {
        AgentControlOutcome.Matched => "matched",
        AgentControlOutcome.Drift => "drift",
        AgentControlOutcome.Unbound => "unbound",
        AgentControlOutcome.AppliedPendingConfirmation => "appliedPendingConfirmation",
        AgentControlOutcome.Confirmed => "confirmed",
        AgentControlOutcome.RolledBack => "rolledBack",
        AgentControlOutcome.Rejected => "rejected",
        AgentControlOutcome.Busy => "busy",
        AgentControlOutcome.Unavailable => "unavailable",
        AgentControlOutcome.Denied => "denied",
        AgentControlOutcome.InvalidRequest => "invalidRequest",
        _ => throw new ArgumentOutOfRangeException(nameof(outcome)),
    };

    private static AgentControlOutcome? ParseOutcome(string? value) => value switch
    {
        "matched" => AgentControlOutcome.Matched,
        "drift" => AgentControlOutcome.Drift,
        "unbound" => AgentControlOutcome.Unbound,
        "appliedPendingConfirmation" => AgentControlOutcome.AppliedPendingConfirmation,
        "confirmed" => AgentControlOutcome.Confirmed,
        "rolledBack" => AgentControlOutcome.RolledBack,
        "rejected" => AgentControlOutcome.Rejected,
        "busy" => AgentControlOutcome.Busy,
        "unavailable" => AgentControlOutcome.Unavailable,
        "denied" => AgentControlOutcome.Denied,
        "invalidRequest" => AgentControlOutcome.InvalidRequest,
        _ => null,
    };

    private static string PhaseName(ApplyPhase phase) => phase switch
    {
        ApplyPhase.Prepared => "prepared",
        ApplyPhase.RollbackArmed => "rollbackArmed",
        ApplyPhase.AwaitingConfirmation => "awaitingConfirmation",
        ApplyPhase.Confirmed => "confirmed",
        ApplyPhase.RollbackRequired => "rollbackRequired",
        ApplyPhase.RolledBack => "rolledBack",
        ApplyPhase.RecoveryRequired => "recoveryRequired",
        _ => throw new ArgumentOutOfRangeException(nameof(phase)),
    };

    private static ApplyPhase? ParsePhase(string? value) => value switch
    {
        "prepared" => ApplyPhase.Prepared,
        "rollbackArmed" => ApplyPhase.RollbackArmed,
        "awaitingConfirmation" => ApplyPhase.AwaitingConfirmation,
        "confirmed" => ApplyPhase.Confirmed,
        "rollbackRequired" => ApplyPhase.RollbackRequired,
        "rolledBack" => ApplyPhase.RolledBack,
        "recoveryRequired" => ApplyPhase.RecoveryRequired,
        _ => null,
    };

    private static bool Properties(JsonElement root, params string[] names) => root.ValueKind == JsonValueKind.Object &&
        root.EnumerateObject().Select(property => property.Name).Order(StringComparer.Ordinal).SequenceEqual(names.Order(StringComparer.Ordinal));

    private static bool Duplicates(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                if (!seen.Add(property.Name) || Duplicates(property.Value)) { return true; }
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var value in element.EnumerateArray())
            {
                if (Duplicates(value)) { return true; }
            }
        }

        return false;
    }
}

/// <summary>Decoded agent control request or stable rejection code.</summary>
public sealed class ControlRequestResult
{
    internal ControlRequestResult(AgentControlRequest? request, string? errorCode) { Request = request; ErrorCode = errorCode; }
    /// <summary>Gets the validated request, or null if decoding failed.</summary>
    public AgentControlRequest? Request { get; }
    /// <summary>Gets whether decoding succeeded.</summary>
    public bool IsValid => Request is not null;
    /// <summary>Gets the stable error code, or null on success.</summary>
    public string? ErrorCode { get; }
}

/// <summary>Decoded agent control reply or stable rejection code.</summary>
public sealed class ControlReplyResult
{
    internal ControlReplyResult(AgentControlReply? reply, string? errorCode) { Reply = reply; ErrorCode = errorCode; }
    /// <summary>Gets the validated reply, or null if decoding failed.</summary>
    public AgentControlReply? Reply { get; }
    /// <summary>Gets whether decoding succeeded.</summary>
    public bool IsValid => Reply is not null;
    /// <summary>Gets the stable error code, or null on success.</summary>
    public string? ErrorCode { get; }
}
