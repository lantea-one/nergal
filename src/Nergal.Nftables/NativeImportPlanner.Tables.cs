using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Nergal.Core.Controller;
using Nergal.Core.Policy;

namespace Nergal.Nftables;

public static partial class NativeImportPlanner
{
    private sealed partial class Planner
    {
        private void ReadRoot(Unit unit, Term[] terms, Scope scope, int depth)
        {
            var first = terms[0]; var command = first.Text is "add" or "create";
            var head = command ? terms[1..] : terms;
            Require(head.Length > 0, first, "import.commandUnsupported");
            if (command && head[0].Text is "chain" or "rule" or "set")
            {
                Require(first.Text == "add" && head.Length >= 4, first, "import.commandUnsupported");
                Require(tables.TryGetValue(Key(head[1].Text, Name(head[2])), out var existing), first, "import.tableMissing");
                if (head[0].Text == "rule")
                {
                    Require(head.Length >= 5 && existing!.Chains.TryGetValue(Name(head[3]), out _), first, "import.chainMissing");
                    existing!.Chains[Name(head[3])].Rules.Add((first, Expand(head[4..], scope, 0))); return;
                }
                var synthetic = new[] { head[0], head[3] }.Concat(head[4..]).ToArray();
                if (head[0].Text == "chain" && head.Length == 4)
                {
                    var chainName = Name(head[3]); Require(!existing!.Chains.ContainsKey(chainName), first, "import.chainDuplicateOrLimit");
                    existing.Chains.Add(chainName, new Chain(chainName, first, new Scope(scope))); Map(first, "chain", existing.Role.ToString()); return;
                }
                ReadTable(unit, synthetic, scope, existing!, depth); Map(first, "command-definition", existing!.Role.ToString()); return;
            }
            Require(head.Length >= 2 && head[0].Text == "table", first, "import.rootStatementUnsupported");
            var body = head[^1].Node.Kind == NativeSourceNodeKind.Braces ? head[^1] : null;
            var length = head.Length - (body is null ? 0 : 1);
            Require(length is 2 or 3 && (!command || first.Text is "add" or "create"), first);
            var family = length == 3 ? head[1].Text : "ip"; var name = Name(head[length - 1]);
            var binding = request.Tables.SingleOrDefault(b => b.Family == family && b.Name == name);
            Require(binding is not null, first, "import.tableMappingRequired");
            Require((family == "inet" && binding!.Role != NativeImportTableRole.Bridge) || (family == "bridge" && binding!.Role == NativeImportTableRole.Bridge), first, "import.tableFamilyUnsupported");
            Require(!tables.ContainsKey(Key(family, name)), first, "import.tableDuplicate");
            var table = new Table(family, name, first, binding!.Role); tables.Add(Key(family, name), table);
            Map(first, "table-role", table.Role.ToString());
            if (body is not null)
            { Read(unit, NativeSourceDeclarationParser.Partition(unit.Analysis.Lexical.Document!, body.Node.Children, false), new Scope(scope), table, null, depth); }
        }

        private void ReadTable(Unit unit, Term[] terms, Scope scope, Table table, int depth)
        {
            var first = terms[0];
            Require(terms.Length == 3 && terms[^1].Node.Kind == NativeSourceNodeKind.Braces, first, "import.tableStatementUnsupported");
            var name = Name(terms[1]);
            if (first.Text == "chain")
            {
                Require(!table.Chains.ContainsKey(name) && table.Chains.Count < 35, first, "import.chainDuplicateOrLimit");
                var chain = new Chain(name, first, new Scope(scope)); table.Chains.Add(name, chain);
                Map(first, "chain", table.Role.ToString());
                Read(unit, NativeSourceDeclarationParser.Partition(unit.Analysis.Lexical.Document!, terms[^1].Node.Children, true), chain.Scope, table, chain, depth);
                return;
            }
            Require(first.Text == "set" && !table.Sets.ContainsKey(name), first, "import.objectUnsupported");
            ReadSet(terms[2], scope, table, name); Map(first, "named-object", table.Role.ToString());
        }

        private void ReadChain(Term[] terms, Scope scope, Table table, Chain chain)
        {
            var first = terms[0];
            if (first.Text == "type")
            {
                var t = Expand(terms, scope, 0);
                Require(chain.Type is null && t.Length == 6 && t[2].Text == "hook" && t[4].Text == "priority", first, "import.chainHeaderUnsupported");
                chain.Type = t[1].Text; chain.Hook = t[3].Text; chain.Priority = Priority(t[5], table.Family, chain.Hook);
                Map(first, "chain-header", table.Role.ToString()); return;
            }
            if (first.Text == "policy")
            {
                Require(!chain.HasPolicy && terms.Length == 2 && terms[1].Text is "accept" or "drop", first, "import.chainPolicyUnsupported");
                chain.HasPolicy = true; chain.Policy = terms[1].Text; Map(first, "chain-policy", table.Role.ToString()); return;
            }
            chain.Rules.Add((first, Expand(terms, scope, 0)));
        }

        private static int Priority(Term term, string family, string hook)
        {
            if (int.TryParse(term.Text, System.Globalization.NumberStyles.AllowLeadingSign, System.Globalization.CultureInfo.InvariantCulture, out var number)) { return number; }
            return (family, term.Text, hook) switch
            {
                ("inet", "raw", _) => -300,
                ("inet", "mangle", _) => -150,
                ("inet", "filter", _) => 0,
                ("inet", "security", _) => 50,
                ("inet", "dstnat", "prerouting") => -100,
                ("inet", "srcnat", "postrouting") => 100,
                ("bridge", "filter", _) => -200,
                ("bridge", "dstnat", "prerouting") => -300,
                ("bridge", "srcnat", "postrouting") => 300,
                ("bridge", "out", "output") => 100,
                _ => throw new ImportFailure("import.priorityUnsupported", term),
            };
        }

        private void ReadSet(Term body, Scope scope, Table table, string name)
        {
            string? type = null; Term[]? values = null; var flags = new HashSet<string>(StringComparer.Ordinal); int? size = null;
            foreach (var statement in NativeSourceDeclarationParser.Partition(body.Unit.Analysis.Lexical.Document!, body.Node.Children, false))
            {
                var terms = Expand(Terms(body.Unit, statement.Nodes), scope, 0); if (terms.Length == 0) { continue; }
                var first = terms[0];
                switch (first.Text)
                {
                    case "type": Require(type is null && terms.Length == 2, first); type = terms[1].Text; break;
                    case "flags":
                        Require(flags.Count == 0, first);
                        foreach (var flag in Comma(terms[1..], first)) { Require(flags.Add(flag.Text) && flag.Text is "constant" or "interval" or "dynamic" or "timeout", flag, "import.setFlagsUnsupported"); }
                        break;
                    case "size": Require(size is null && terms.Length == 2, first); size = Integer(terms[1]); break;
                    case "elements": Require(values is null && terms.Length == 3 && terms[1].Text == "=" && terms[2].Node.Kind == NativeSourceNodeKind.Braces, first); values = Expand(Comma(terms[2].Children, first), scope, 0); break;
                    default: throw new ImportFailure("import.setOptionUnsupported", first);
                }
            }
            Require(type is not null, body, "import.setTypeRequired");
            if (flags.Contains("dynamic") || flags.Contains("timeout"))
            {
                Require(values is null && flags.SetEquals(["dynamic", "timeout"]) && size == 65535 && type is "ipv4_addr" or "ipv6_addr", body, "import.dynamicSetUnsupported");
                table.Sets.Add(name, new(null, type)); return;
            }
            Require(size is null && values is { Length: >= 1 and <= 64 }, body, "import.staticSetUnsupported");
            var field = type switch { "ipv4_addr" => NativeRuleField.IpSource, "ipv6_addr" => NativeRuleField.Ip6Source, "inet_service" => NativeRuleField.TcpDestinationPort, _ => throw new ImportFailure("import.setTypeUnsupported", body) };
            var entries = values!.Select(v => Literal(field, v)).Select(v => v switch
            {
                NativeAddressLiteral a => a.Prefix.Value,
                NativePortLiteral p => p.Port.ToString(System.Globalization.CultureInfo.InvariantCulture),
                _ => throw new ImportFailure("import.setValueUnsupported", body),
            }).ToArray();
            var hash = SHA256.HashData(Encoding.UTF8.GetBytes(body.SourceId.ToString("D") + "\0" + table.Family + "\0" + table.Name + "\0" + name));
            var id = new Guid(hash.AsSpan(0, 16));
            var content = new ReusableObjectContent("import_" + Convert.ToHexStringLower(hash.AsSpan(0, 12)), type == "ipv4_addr" ? ReusableObjectKind.Ipv4 : type == "ipv6_addr" ? ReusableObjectKind.Ipv6 : ReusableObjectKind.Port, "Imported native set " + name, entries);
            table.Sets.Add(name, new(new(id, 1, content, true), null));
        }

        internal static Term[] Comma(Term[] terms, Term origin)
        {
            var values = new List<Term>();
            for (var i = 0; i < terms.Length; i++)
            { Require(i % 2 == 0 ? terms[i].Text != "," : terms[i].Text == ",", terms[i], "import.listUnsupported"); if (i % 2 == 0) { values.Add(terms[i]); } }
            Require(terms.Length > 0 && terms.Length % 2 == 1, origin, "import.listUnsupported"); return values.ToArray();
        }
        private static NativeRuleLiteral Literal(NativeRuleField field, Term term) =>
            NativeRuleExpressionParser.ReadLiteral(term.Unit.Analysis.Lexical.Document!, field, term.Node) ?? throw new ImportFailure("import.literalUnsupported", term);
    }
}
