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

        if (request.Policy is { } policy)
        {
            writer.WritePropertyName("policy");
            WritePolicy(writer, policy);
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
                var validProps = hasWatchdog
                    ? Properties(root, "schemaVersion", "command", "operationId", "watchdogId", "confirmationTimeoutSeconds", "policy")
                    : Properties(root, "schemaVersion", "command", "operationId", "confirmationTimeoutSeconds", "policy");
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

                var policy = ParsePolicy(root.GetProperty("policy"));
                if (policy is null)
                {
                    return new(null, "request.policy");
                }

                return new(new AgentControlRequest(AgentControlCommand.PrepareApply, opId, wdId, timeout, policy), null);
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

    private static void WritePolicy(Utf8JsonWriter writer, FilterPolicy policy)
    {
        writer.WriteStartObject();
        writer.WriteNumber("schemaVersion", policy.SchemaVersion);
        writer.WriteString("inputDefaultVerdict", VerdictName(policy.InputDefaultVerdict));
        writer.WriteString("forwardDefaultVerdict", VerdictName(policy.ForwardDefaultVerdict));
        writer.WriteString("outputDefaultVerdict", VerdictName(policy.OutputDefaultVerdict));
        writer.WriteStartArray("rules");
        foreach (var draft in policy.Rules)
        {
            if (draft is null)
            {
                throw new ArgumentException("Null rules cannot be serialized.");
            }

            writer.WriteStartObject();
            writer.WriteString("family", draft.Family == IpFamily.IPv4 ? "ipv4" : "ipv6");
            writer.WriteString("protocol", ProtocolName(draft.Protocol));
            writer.WriteString("verdict", VerdictName(draft.Verdict));
            if (draft.Source is not null) { writer.WriteString("source", draft.Source.Value); }
            if (draft.Destination is not null) { writer.WriteString("destination", draft.Destination.Value); }
            if (draft.DestinationPort is { } dport) { writer.WriteNumber("destinationPort", dport); }
            writer.WriteString("chain", ChainName(draft.Chain));
            if (draft.InputInterface is not null) { writer.WriteString("inputInterface", draft.InputInterface); }
            if (draft.OutputInterface is not null) { writer.WriteString("outputInterface", draft.OutputInterface); }
            writer.WriteNumber("connectionStates", (int)draft.ConnectionStates);
            if (draft.IcmpType is not null) { writer.WriteString("icmpType", draft.IcmpType); }
            if (draft.RateLimit is { } rl)
            {
                writer.WriteStartObject("rateLimit");
                writer.WriteNumber("packetsPerWindow", rl.PacketsPerWindow);
                writer.WriteString("windowUnit", rl.WindowUnit == RateLimitTimeUnit.Second ? "second" : "minute");
                writer.WriteNumber("burst", rl.Burst);
                writer.WriteNumber("entryTimeoutSeconds", rl.EntryTimeoutSeconds);
                writer.WriteEndObject();
            }

            if (draft.MatchOriginalDestinationDnat)
            {
                writer.WriteBoolean("matchOriginalDestinationDnat", true);
            }

            writer.WriteEndObject();
        }

        writer.WriteEndArray();
        writer.WriteEndObject();
    }

    private static FilterPolicy? ParsePolicy(JsonElement element)
    {
        if (element.ValueKind != JsonValueKind.Object ||
            !Properties(element, "schemaVersion", "inputDefaultVerdict", "forwardDefaultVerdict", "outputDefaultVerdict", "rules"))
        {
            return null;
        }

        var verEl = element.GetProperty("schemaVersion");
        if (verEl.ValueKind != JsonValueKind.Number || !verEl.TryGetInt32(out var schemaVersion) || schemaVersion is not (1 or 2))
        {
            return null;
        }

        var inDef = ParseVerdict(element.GetProperty("inputDefaultVerdict"));
        var fwdDef = ParseVerdict(element.GetProperty("forwardDefaultVerdict"));
        var outDef = ParseVerdict(element.GetProperty("outputDefaultVerdict"));
        if (inDef is null || fwdDef is null || outDef is null)
        {
            return null;
        }

        var rulesEl = element.GetProperty("rules");
        if (rulesEl.ValueKind != JsonValueKind.Array || rulesEl.GetArrayLength() > MaximumRuleCount)
        {
            return null;
        }

        var allowedRuleKeys = new HashSet<string>(
            ["family", "protocol", "verdict", "source", "destination", "destinationPort", "chain",
             "inputInterface", "outputInterface", "connectionStates", "icmpType", "rateLimit", "matchOriginalDestinationDnat"],
            StringComparer.Ordinal);
        var rules = new List<FilterRule>(rulesEl.GetArrayLength());

        foreach (var item in rulesEl.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.Object) { return null; }
            foreach (var p in item.EnumerateObject())
            {
                if (!allowedRuleKeys.Contains(p.Name)) { return null; }
            }

            if (!item.TryGetProperty("family", out var famEl) || famEl.ValueKind != JsonValueKind.String ||
                !item.TryGetProperty("protocol", out var protoEl) || protoEl.ValueKind != JsonValueKind.String ||
                !item.TryGetProperty("verdict", out var verdEl) ||
                !item.TryGetProperty("chain", out var chainEl) || chainEl.ValueKind != JsonValueKind.String ||
                !item.TryGetProperty("connectionStates", out var ctEl) || ctEl.ValueKind != JsonValueKind.Number ||
                !ctEl.TryGetInt32(out var ctRaw))
            {
                return null;
            }

            IpFamily? family = famEl.GetString() switch { "ipv4" => IpFamily.IPv4, "ipv6" => IpFamily.IPv6, _ => null };
            var protocol = ParseProtocol(protoEl.GetString());
            var verdict = ParseVerdict(verdEl);
            var chain = ParseChain(chainEl.GetString());
            if (family is null || protocol is null || verdict is null || chain is null) { return null; }
            var ctStates = (ConnectionStateFlags)ctRaw;
            if ((ctStates & ~FilterPolicyValidation.AllConnectionStates) != 0) { return null; }

            NetworkPrefix? source = null;
            if (item.TryGetProperty("source", out var srcEl))
            {
                if (srcEl.ValueKind != JsonValueKind.String) { return null; }
                source = new NetworkPrefix(srcEl.GetString()!);
            }

            NetworkPrefix? destination = null;
            if (item.TryGetProperty("destination", out var dstEl))
            {
                if (dstEl.ValueKind != JsonValueKind.String) { return null; }
                destination = new NetworkPrefix(dstEl.GetString()!);
            }

            int? dport = null;
            if (item.TryGetProperty("destinationPort", out var dpEl))
            {
                if (dpEl.ValueKind != JsonValueKind.Number || !dpEl.TryGetInt32(out var p)) { return null; }
                dport = p;
            }

            string? iif = null;
            if (item.TryGetProperty("inputInterface", out var iifEl))
            {
                if (iifEl.ValueKind != JsonValueKind.String) { return null; }
                iif = iifEl.GetString();
            }

            string? oif = null;
            if (item.TryGetProperty("outputInterface", out var oifEl))
            {
                if (oifEl.ValueKind != JsonValueKind.String) { return null; }
                oif = oifEl.GetString();
            }

            string? icmpType = null;
            if (item.TryGetProperty("icmpType", out var icmpEl))
            {
                if (icmpEl.ValueKind != JsonValueKind.String) { return null; }
                icmpType = icmpEl.GetString();
            }

            PerSourceRateLimit? rateLimit = null;
            if (item.TryGetProperty("rateLimit", out var rlEl))
            {
                if (!Properties(rlEl, "packetsPerWindow", "windowUnit", "burst", "entryTimeoutSeconds")) { return null; }
                var ppwEl = rlEl.GetProperty("packetsPerWindow");
                var unitEl = rlEl.GetProperty("windowUnit");
                var burstEl = rlEl.GetProperty("burst");
                var toEl = rlEl.GetProperty("entryTimeoutSeconds");
                if (ppwEl.ValueKind != JsonValueKind.Number || !ppwEl.TryGetInt32(out var ppw) ||
                    unitEl.ValueKind != JsonValueKind.String ||
                    burstEl.ValueKind != JsonValueKind.Number || !burstEl.TryGetInt32(out var burst) ||
                    toEl.ValueKind != JsonValueKind.Number || !toEl.TryGetInt32(out var timeout))
                {
                    return null;
                }

                RateLimitTimeUnit? unit = unitEl.GetString() switch
                {
                    "second" => RateLimitTimeUnit.Second,
                    "minute" => RateLimitTimeUnit.Minute,
                    _ => null,
                };
                if (unit is null) { return null; }
                rateLimit = new(ppw, unit.Value, burst, timeout);
            }

            var matchDnat = false;
            if (item.TryGetProperty("matchOriginalDestinationDnat", out var dnatEl))
            {
                if (dnatEl.ValueKind is not (JsonValueKind.True or JsonValueKind.False)) { return null; }
                matchDnat = dnatEl.GetBoolean();
            }

            rules.Add(new(family.Value, protocol.Value, verdict.Value, source, destination, dport,
                chain.Value, iif, oif, ctStates, icmpType, rateLimit, matchDnat));
        }

        return new(schemaVersion, inDef.Value, fwdDef.Value, outDef.Value, rules);
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

    private static string VerdictName(FilterVerdict v) => v switch
    {
        FilterVerdict.Accept => "accept",
        FilterVerdict.Drop => "drop",
        _ => throw new ArgumentOutOfRangeException(nameof(v)),
    };

    private static FilterVerdict? ParseVerdict(JsonElement el) => el.ValueKind == JsonValueKind.String ? el.GetString() switch
    {
        "accept" => FilterVerdict.Accept,
        "drop" => FilterVerdict.Drop,
        _ => null,
    } : null;

    private static string ProtocolName(FilterProtocol p) => p switch
    {
        FilterProtocol.Any => "any",
        FilterProtocol.Tcp => "tcp",
        FilterProtocol.Udp => "udp",
        FilterProtocol.Icmp => "icmp",
        FilterProtocol.IcmpV6 => "icmpv6",
        _ => throw new ArgumentOutOfRangeException(nameof(p)),
    };

    private static FilterProtocol? ParseProtocol(string? v) => v switch
    {
        "any" => FilterProtocol.Any,
        "tcp" => FilterProtocol.Tcp,
        "udp" => FilterProtocol.Udp,
        "icmp" => FilterProtocol.Icmp,
        "icmpv6" => FilterProtocol.IcmpV6,
        _ => null,
    };

    private static string ChainName(FilterChainKind c) => c switch
    {
        FilterChainKind.Input => "input",
        FilterChainKind.Forward => "forward",
        FilterChainKind.Output => "output",
        _ => throw new ArgumentOutOfRangeException(nameof(c)),
    };

    private static FilterChainKind? ParseChain(string? v) => v switch
    {
        "input" => FilterChainKind.Input,
        "forward" => FilterChainKind.Forward,
        "output" => FilterChainKind.Output,
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
