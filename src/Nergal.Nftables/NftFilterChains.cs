using System.Globalization;
using Nergal.Core.Policy;

namespace Nergal.Nftables;

// The prefix makes validated local identifiers disjoint from nft keywords and all base chains.
internal static class NftFilterChains
{
    internal const string Prefix = "ngc_";

    internal static bool IsName(string? name) => name is { Length: >= 1 and <= 32 } &&
        name.All(c => char.IsAsciiLetterOrDigit(c) || c == '_');

    internal static string? FromNative(string? name) =>
        name?.StartsWith(Prefix, StringComparison.Ordinal) == true && IsName(name[Prefix.Length..]) ? name[Prefix.Length..] : null;

    internal static void Validate(FilterPolicy policy, List<PolicyDiagnostic> errors)
    {
        var graph = new Dictionary<string, HashSet<string>>(StringComparer.Ordinal);
        if (policy.RegularChains.Count > 32 || (policy.RegularChains.Count != 0 && policy.SchemaVersion != 2))
        { errors.Add(new("chain.declarationsUnsupported", "regularChains")); return; }
        foreach (var name in policy.RegularChains)
        {
            if (!IsName(name) || !graph.TryAdd(name, new(StringComparer.Ordinal)))
            { errors.Add(new("chain.invalidName", "regularChains")); return; }
        }
        for (var i = 0; i < policy.Rules.Count; i++)
        {
            if (policy.Rules[i] is not { } rule) { continue; }
            var path = "rules[" + i.ToString(CultureInfo.InvariantCulture) + "]";
            var regular = rule.Chain == FilterChainKind.Regular;
            if (regular != (rule.RegularChain is not null) || (regular && !graph.ContainsKey(rule.RegularChain!)))
            { errors.Add(new("chain.undeclared", path)); continue; }
            if ((rule.Verdict == FilterVerdict.Jump) != (rule.JumpTarget is not null) ||
                (rule.JumpTarget is { } target && !graph.ContainsKey(target)))
            { errors.Add(new("jump.invalidTarget", path)); continue; }
            if (rule.Verdict == FilterVerdict.Return && !regular)
            { errors.Add(new("return.requiresRegularChain", path)); }
            if (regular && rule.JumpTarget is not null) { graph[rule.RegularChain!].Add(rule.JumpTarget); }
        }

        // Include disabled and unreachable edges. Memoize completed subgraphs to bound work on shared callees.
        var active = new HashSet<string>(StringComparer.Ordinal);
        var depths = new Dictionary<string, int>(StringComparer.Ordinal);
        int Depth(string name)
        {
            if (depths.TryGetValue(name, out var depth)) { return depth; }
            if (!active.Add(name)) { return 9; }
            depth = 1;
            foreach (var child in graph[name]) { depth = Math.Max(depth, 1 + Depth(child)); }
            active.Remove(name);
            depths.Add(name, depth);
            return depth;
        }
        if (graph.Keys.Any(name => Depth(name) > 8)) { errors.Add(new("jump.cycleOrDepth", "regularChains")); }
        if (errors.Count > 0 || graph.Count == 0) { return; }

        // Keep the base-hook matcher restrictions through every possible caller, including disabled calls.
        var reachable = new HashSet<(FilterChainKind Hook, string Name)>();
        void Mark(FilterChainKind hook, string name)
        {
            if (!reachable.Add((hook, name))) { return; }
            foreach (var child in graph[name]) { Mark(hook, child); }
        }
        foreach (var rule in policy.Rules)
        {
            if (rule is { Chain: not FilterChainKind.Regular, JumpTarget: { } called }) { Mark(rule.Chain, called); }
        }
        for (var index = 0; index < policy.Rules.Count; index++)
        {
            if (policy.Rules[index] is not { RegularChain: { } name } rule) { continue; }
            if ((reachable.Contains((FilterChainKind.Input, name)) && rule.OutputInterface is not null) ||
                (reachable.Contains((FilterChainKind.Output, name)) && (rule.InputInterface is not null || rule.SourceMac is not null || rule.SourceMacs is not null)))
            { errors.Add(new("chain.callerHookMismatch", "rules[" + index.ToString(CultureInfo.InvariantCulture) + "]")); }
        }
    }
}
