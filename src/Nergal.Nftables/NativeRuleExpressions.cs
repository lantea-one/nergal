using Nergal.Core.Policy;

namespace Nergal.Nftables;

/// <summary>A supported native payload/meta field; no implicit IP family is added.</summary>
public enum NativeRuleField
{
    /// <summary>IPv4 source address.</summary>
    IpSource,
    /// <summary>IPv4 destination address.</summary>
    IpDestination,
    /// <summary>IPv6 source address.</summary>
    Ip6Source,
    /// <summary>IPv6 destination address.</summary>
    Ip6Destination,
    /// <summary>Ethernet source address.</summary>
    EtherSource,
    /// <summary>Ethernet destination address.</summary>
    EtherDestination,
    /// <summary>TCP source port.</summary>
    TcpSourcePort,
    /// <summary>TCP destination port.</summary>
    TcpDestinationPort,
    /// <summary>UDP source port.</summary>
    UdpSourcePort,
    /// <summary>UDP destination port.</summary>
    UdpDestinationPort,
    /// <summary>Ingress interface name.</summary>
    InputInterface,
    /// <summary>Egress interface name.</summary>
    OutputInterface,
    /// <summary>Ingress bridge master name.</summary>
    InputBridge,
    /// <summary>Egress bridge master name.</summary>
    OutputBridge,
}

/// <summary>A private typed literal with exact original provenance and a value-free string representation.</summary>
public abstract class NativeRuleLiteral
{
    internal NativeRuleLiteral(NativeSourceSpan span) { Span = span; }
    /// <summary>Gets the original literal position before normalization.</summary>
    public NativeSourceSpan Span { get; }
    /// <summary>Returns position only; callers must not log private typed properties.</summary>
    public override string ToString() => $"Native literal at {Span.Line}:{Span.Column}";
}

/// <summary>A validated numeric IP prefix, including exact hosts represented as /32 or /128.</summary>
public sealed class NativeAddressLiteral : NativeRuleLiteral
{
    internal NativeAddressLiteral(NativeSourceSpan span, NetworkPrefix prefix) : base(span) { Prefix = prefix; }
    /// <summary>Gets the private canonical prefix; this is not a policy mapping.</summary>
    public NetworkPrefix Prefix { get; }
}

/// <summary>A validated numeric Ethernet address.</summary>
public sealed class NativeMacLiteral : NativeRuleLiteral
{
    internal NativeMacLiteral(NativeSourceSpan span, MacAddress address) : base(span) { Address = address; }
    /// <summary>Gets the private canonical address.</summary>
    public MacAddress Address { get; }
}

/// <summary>A numeric source port, without policy compatibility assumptions.</summary>
public sealed class NativePortLiteral : NativeRuleLiteral
{
    internal NativePortLiteral(NativeSourceSpan span, ushort port) : base(span) { Port = port; }
    /// <summary>Gets the source value, including zero; later policy validation may reject it.</summary>
    public ushort Port { get; }
}

/// <summary>An exact interface name without wildcard or escape interpretation.</summary>
public sealed class NativeInterfaceLiteral : NativeRuleLiteral
{
    internal NativeInterfaceLiteral(NativeSourceSpan span, string name) : base(span) { Name = name; }
    /// <summary>Gets the private unescaped exact name.</summary>
    public string Name { get; }
}

/// <summary>One ordered conjunction predicate, retaining repeats rather than overwriting another field.</summary>
public sealed class NativeRuleMatch
{
    internal NativeRuleMatch(NativeRuleField field, bool negated, NativeSourceSpan span, IEnumerable<NativeRuleLiteral> values)
    { Field = field; Negated = negated; Span = span; Values = Array.AsReadOnly(values.ToArray()); }
    /// <summary>Gets the exact native field.</summary>
    public NativeRuleField Field { get; }
    /// <summary>Gets whether this predicate uses != rather than equality.</summary>
    public bool Negated { get; }
    /// <summary>Gets the complete original predicate position.</summary>
    public NativeSourceSpan Span { get; }
    /// <summary>Gets a nonempty immutable literal membership list in source order.</summary>
    public IReadOnlyList<NativeRuleLiteral> Values { get; }
    /// <summary>Returns kind and position only, never private values.</summary>
    public override string ToString() => $"{Field} at {Span.Line}:{Span.Column}";
}

/// <summary>Terminal actions in the initial native expression grammar.</summary>
public enum NativeRuleVerdict
{
    /// <summary>Accept, without inferring final acceptance by other base chains.</summary>
    Accept,
    /// <summary>Drop.</summary>
    Drop,
    /// <summary>Return, with caller/base-chain meaning still requiring contextual mapping.</summary>
    Return,
    /// <summary>Exactly reject with icmpx type admin-prohibited.</summary>
    RejectAdminProhibited,
}

/// <summary>A completely consumed rule in the declared expression slice; never an executable policy.</summary>
public sealed class NativeParsedRule
{
    internal NativeParsedRule(NativeSourceStatement statement, IEnumerable<NativeRuleMatch> matches, NativeRuleVerdict verdict, NativeSourceSpan verdictSpan)
    { Statement = statement; Matches = Array.AsReadOnly(matches.ToArray()); Verdict = verdict; VerdictSpan = verdictSpan; }
    /// <summary>Gets the unchanged original statement, including all trivia.</summary>
    public NativeSourceStatement Statement { get; }
    /// <summary>Gets immutable conjunction predicates in original order, including repeats.</summary>
    public IReadOnlyList<NativeRuleMatch> Matches { get; }
    /// <summary>Gets the parsed terminal action; context and ownership are unresolved.</summary>
    public NativeRuleVerdict Verdict { get; }
    /// <summary>Gets the action's complete original position.</summary>
    public NativeSourceSpan VerdictSpan { get; }
    /// <summary>Returns counts only, never private source values.</summary>
    public override string ToString() => $"Native rule ({Matches.Count} predicates; conversion blocked)";
}

/// <summary>A stable, value-free reason why a whole rule has no typed result.</summary>
public sealed record NativeRuleDiagnostic(string Code, NativeSourceSpan Span);

/// <summary>A complete typed rule or one diagnostic; a successfully parsed prefix is never exposed.</summary>
public sealed class NativeRuleParseEntry
{
    internal NativeRuleParseEntry(NativeSourceStatement statement, NativeParsedRule? rule, NativeRuleDiagnostic? diagnostic)
    { Statement = statement; Rule = rule; Diagnostic = diagnostic; }
    /// <summary>Gets the unchanged source statement even when parsing fails.</summary>
    public NativeSourceStatement Statement { get; }
    /// <summary>Gets the whole rule on success, or null on any unsupported/unresolved input.</summary>
    public NativeParsedRule? Rule { get; }
    /// <summary>Gets the failure code/position, or null on success.</summary>
    public NativeRuleDiagnostic? Diagnostic { get; }
}

/// <summary>Value-free rule parsing counts and failures, safe for a source-bound review report.</summary>
public sealed class NativeRuleParsingSummary
{
    internal NativeRuleParsingSummary(bool available, int total, int parsed, IEnumerable<NativeRuleDiagnostic> diagnostics)
    { IsAvailable = available; TotalRules = total; ParsedRules = parsed; Diagnostics = Array.AsReadOnly(diagnostics.ToArray()); }
    /// <summary>Gets whether complete source structure permitted rule enumeration; not whole-file compatibility.</summary>
    public bool IsAvailable { get; }
    /// <summary>Gets the number of chain-local rule statements considered.</summary>
    public int TotalRules { get; }
    /// <summary>Gets completely consumed rules in this limited grammar, without mapping authority.</summary>
    public int ParsedRules { get; }
    /// <summary>Gets immutable diagnostic codes/positions for rules with no typed result.</summary>
    public IReadOnlyList<NativeRuleDiagnostic> Diagnostics { get; }
    internal static NativeRuleParsingSummary Unavailable { get; } = new(false, 0, 0, []);
}

/// <summary>Rule results over the same original declarations; private AST values must not enter reports/logs.</summary>
public sealed class NativeRuleCatalog
{
    internal NativeRuleCatalog(NativeSourceDeclarations declarations, IEnumerable<NativeRuleParseEntry> entries)
    {
        Declarations = declarations; Entries = Array.AsReadOnly(entries.ToArray());
        Summary = new(true, Entries.Count, Entries.Count(e => e.Rule is not null), Entries.Where(e => e.Diagnostic is not null).Select(e => e.Diagnostic!));
    }
    /// <summary>Gets the same source declaration catalog, with unresolved scope/control-flow metadata.</summary>
    public NativeSourceDeclarations Declarations { get; }
    /// <summary>Gets one result for every chain-local rule in source order.</summary>
    public IReadOnlyList<NativeRuleParseEntry> Entries { get; }
    /// <summary>Gets only value-free counts/positions suitable for serialization.</summary>
    public NativeRuleParsingSummary Summary { get; }
    /// <summary>Returns counts only, never private source values.</summary>
    public override string ToString() => $"Native rules ({Summary.ParsedRules}/{Summary.TotalRules}; conversion blocked)";
}
