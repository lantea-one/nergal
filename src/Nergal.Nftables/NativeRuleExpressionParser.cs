using System.Globalization;
using System.Net;
using System.Net.Sockets;
using Nergal.Core.Policy;

namespace Nergal.Nftables;

/// <summary>Consumes complete rule statements in a bounded literal grammar without execution or name resolution.</summary>
public static class NativeRuleExpressionParser
{
    /// <summary>Maximum ordered predicates in one completely parsed rule.</summary>
    public const int MaximumPredicates = 128;
    /// <summary>Maximum literal elements in an anonymous set; exceeding the bound never truncates it.</summary>
    public const int MaximumSetElements = 64;

    /// <summary>Parses every chain-local Rule over the same original document, retaining all failures explicitly.</summary>
    /// <exception cref="ArgumentNullException">The declaration catalog is null.</exception>
    public static NativeRuleCatalog Parse(NativeSourceDeclarations declarations)
    {
        ArgumentNullException.ThrowIfNull(declarations);
        var parser = new Parser(declarations.Structure.Document);
        return new(declarations, Read(declarations.Statements));
        IEnumerable<NativeRuleParseEntry> Read(IEnumerable<NativeSourceStatement> statements)
        {
            foreach (var statement in statements)
            {
                if (statement.Kind == NativeSourceStatementKind.Rule) { yield return parser.Read(statement); }
                foreach (var entry in Read(statement.Children)) { yield return entry; }
            }
        }
    }

    private sealed class Parser(NativeSourceDocument document)
    {
        internal NativeRuleParseEntry Read(NativeSourceStatement statement)
        {
            var nodes = Significant(statement.Nodes, true).ToArray();
            var matches = new List<NativeRuleMatch>(); var i = 0;
            while (i < nodes.Length)
            {
                var start = nodes[i];
                if (Verdict(Word(start)) is { } verdict)
                {
                    var length = verdict == NativeRuleVerdict.RejectAdminProhibited ? 5 : 1;
                    if (length == 5 && (i + length > nodes.Length || Word(nodes[i + 1]) != "with" || Word(nodes[i + 2]) != "icmpx" ||
                        Word(nodes[i + 3]) != "type" || Word(nodes[i + 4]) != "admin-prohibited"))
                    { return Fail("source.ruleVerdictUnsupported", start); }
                    if (i + length != nodes.Length) { return Fail("source.ruleTrailingInput", nodes[i + length]); }
                    return new(statement, new(statement, matches, verdict, Cover(start.Span, nodes[^1].Span)), null);
                }
                if (matches.Count == MaximumPredicates) { return Fail("source.rulePredicateLimit", start); }
                var word = Word(nodes[i++]);
                var meta = word == "meta";
                if (meta)
                {
                    if (i == nodes.Length) { return Fail("source.ruleExpressionUnsupported", start); }
                    word = Word(nodes[i++]);
                }
                NativeRuleField? field = word switch
                {
                    "iifname" => NativeRuleField.InputInterface,
                    "oifname" => NativeRuleField.OutputInterface,
                    "ibrname" => NativeRuleField.InputBridge,
                    "obrname" => NativeRuleField.OutputBridge,
                    _ => null,
                };
                if (field is null && !meta && i < nodes.Length)
                {
                    var key = Word(nodes[i]);
                    field = (word, key) switch
                    {
                        ("ip", "saddr") => NativeRuleField.IpSource,
                        ("ip", "daddr") => NativeRuleField.IpDestination,
                        ("ip6", "saddr") => NativeRuleField.Ip6Source,
                        ("ip6", "daddr") => NativeRuleField.Ip6Destination,
                        ("ether", "saddr") => NativeRuleField.EtherSource,
                        ("ether", "daddr") => NativeRuleField.EtherDestination,
                        ("tcp", "sport") => NativeRuleField.TcpSourcePort,
                        ("tcp", "dport") => NativeRuleField.TcpDestinationPort,
                        ("udp", "sport") => NativeRuleField.UdpSourcePort,
                        ("udp", "dport") => NativeRuleField.UdpDestinationPort,
                        _ => null,
                    };
                    if (field is not null) { i++; }
                }
                if (field is null) { return Fail(Reference(start) ? "source.ruleReferenceUnresolved" : "source.ruleExpressionUnsupported", start); }
                var negated = false;
                if (i < nodes.Length && Text(nodes[i]) is "!=" or "==") { negated = Text(nodes[i++]) == "!="; }
                if (i == nodes.Length) { return Fail("source.ruleValueRequired", nodes[^1]); }
                var value = nodes[i++]; var values = new List<NativeRuleLiteral>();
                if (value.Kind == NativeSourceNodeKind.Braces && !Interface(field.Value))
                {
                    var items = Significant(value.Children).ToArray(); var expectingValue = true;
                    foreach (var item in items)
                    {
                        if (!expectingValue)
                        {
                            if (Text(item) != ",") { return Fail("source.ruleSetUnsupported", item); }
                        }
                        else
                        {
                            if (values.Count == MaximumSetElements) { return Fail("source.ruleSetLimit", item); }
                            var literal = Literal(field.Value, item);
                            if (literal is null) { return Fail(Reference(item) ? "source.ruleReferenceUnresolved" : "source.ruleLiteralUnsupported", item); }
                            values.Add(literal);
                        }
                        expectingValue = !expectingValue;
                    }
                    if (values.Count == 0 || expectingValue) { return Fail("source.ruleSetUnsupported", value); }
                }
                else
                {
                    var literal = Literal(field.Value, value);
                    if (literal is null) { return Fail(Reference(value) ? "source.ruleReferenceUnresolved" : "source.ruleLiteralUnsupported", value); }
                    values.Add(literal);
                }
                matches.Add(new(field.Value, negated, Cover(start.Span, value.Span), values));
            }
            return Fail("source.ruleVerdictRequired", nodes[^1]);

            NativeRuleParseEntry Fail(string code, NativeSourceNode node) => new(statement, null, new(code, node.Span));
        }

        private NativeRuleLiteral? Literal(NativeRuleField field, NativeSourceNode node) => ReadLiteral(document, field, node);

        private static NativeRuleVerdict? Verdict(string word) => word switch
        {
            "accept" => NativeRuleVerdict.Accept,
            "drop" => NativeRuleVerdict.Drop,
            "return" => NativeRuleVerdict.Return,
            "reject" => NativeRuleVerdict.RejectAdminProhibited,
            _ => null,
        };
        private IEnumerable<NativeSourceNode> Significant(IEnumerable<NativeSourceNode> nodes, bool separators = false) => nodes.Where(n => n.Kind != NativeSourceNodeKind.Token ||
            (!document.Tokens[n.StartTokenIndex].IsTrivia && document.Tokens[n.StartTokenIndex].Kind != NativeSourceTokenKind.NewLine && (!separators || Text(n) != ";")));
        private bool Reference(NativeSourceNode node) => node.Kind == NativeSourceNodeKind.Token && document.Tokens[node.StartTokenIndex].Kind is NativeSourceTokenKind.VariableReference or NativeSourceTokenKind.AtReference;
        private string Text(NativeSourceNode node) => node.Kind == NativeSourceNodeKind.Token ? document.GetText(node.StartTokenIndex) : "";
        private string Word(NativeSourceNode node) => node.Kind == NativeSourceNodeKind.Token && document.Tokens[node.StartTokenIndex].Kind == NativeSourceTokenKind.Bare ? Text(node) : "";
        private static NativeSourceSpan Cover(NativeSourceSpan start, NativeSourceSpan end) => start with { Length = end.Offset + end.Length - start.Offset };
    }
    internal static NativeRuleLiteral? ReadLiteral(NativeSourceDocument document, NativeRuleField field, NativeSourceNode node, bool normalizeNativeCidr = false)
    {
        if (node.Kind != NativeSourceNodeKind.Token) { return null; }
        var token = document.Tokens[node.StartTokenIndex]; var text = document.GetText(node.StartTokenIndex);
        if (Interface(field))
        {
            if (token.Kind == NativeSourceTokenKind.DoubleQuoted) { text = text[1..^1]; }
            else if (token.Kind != NativeSourceTokenKind.Bare) { return null; }
            return text.Length is >= 1 and <= 15 && text.All(c => c is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9' or '_' or '.' or ':' or '-')
                ? new NativeInterfaceLiteral(node.Span, text) : null;
        }
        if (token.Kind != NativeSourceTokenKind.Bare) { return null; }
        if (field is NativeRuleField.EtherSource or NativeRuleField.EtherDestination)
        { return MacAddress.TryParse(text, out var mac) ? new NativeMacLiteral(node.Span, mac!) : null; }
        if (field is NativeRuleField.TcpSourcePort or NativeRuleField.TcpDestinationPort or NativeRuleField.UdpSourcePort or NativeRuleField.UdpDestinationPort)
        {
            return Decimal(text) && ushort.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var port)
                ? new NativePortLiteral(node.Span, port) : null;
        }
        var family = field is NativeRuleField.IpSource or NativeRuleField.IpDestination ? IpFamily.IPv4 : IpFamily.IPv6;
        var parts = text.Split('/');
        if (parts.Length > 2 || (parts.Length == 2 && !Decimal(parts[1])) || parts[0].Contains('%') ||
            !IPAddress.TryParse(parts[0], out var address) || address.IsIPv4MappedToIPv6) { return null; }
        var actualFamily = address.AddressFamily == AddressFamily.InterNetwork ? IpFamily.IPv4 : IpFamily.IPv6;
        if (family != actualFamily || (family == IpFamily.IPv4 && !Dotted(parts[0]))) { return null; }
        if (family == IpFamily.IPv6 && parts[0].Contains('.') && !Dotted(parts[0][(parts[0].LastIndexOf(':') + 1)..])) { return null; }
        try
        {
            var cidr = parts.Length == 1 ? text + (family == IpFamily.IPv4 ? "/32" : "/128") : text;
            // nft masks host bits in CIDR selectors. Only the importer opts into
            // that native behavior; guided and typed policy inputs stay strict.
            if (normalizeNativeCidr && IPNetwork.TryParse(cidr, out var network)) { cidr = network.ToString(); }
            var prefix = new NetworkPrefix(cidr);
            return new NativeAddressLiteral(node.Span, prefix);
        }
        catch (ArgumentException) { return null; }
    }

    private static bool Interface(NativeRuleField field) => field is NativeRuleField.InputInterface or NativeRuleField.OutputInterface or NativeRuleField.InputBridge or NativeRuleField.OutputBridge;
    private static bool Decimal(string value) => value.Length > 0 && (value.Length == 1 || value[0] != '0') && value.All(c => c is >= '0' and <= '9');
    private static bool Dotted(string value) => value.Split('.') is { Length: 4 } parts && parts.All(p => Decimal(p) && byte.TryParse(p, NumberStyles.None, CultureInfo.InvariantCulture, out _));

}
