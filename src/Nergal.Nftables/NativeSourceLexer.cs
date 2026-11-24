using System.Text;

namespace Nergal.Nftables;

/// <summary>Lossless lexical categories; none establishes that a token is supported native syntax.</summary>
public enum NativeSourceTokenKind
{
    /// <summary>An uninterpreted unquoted atom, including unknown words or address/number literals.</summary>
    Bare,
    /// <summary>Opaque double-quoted text, including delimiters and escapes.</summary>
    DoubleQuoted,
    /// <summary>Opaque single-quoted text; retained for inventory, not certified as native syntax.</summary>
    SingleQuoted,
    /// <summary>A dollar-prefixed symbolic reference; never interpreted as a keyword.</summary>
    VariableReference,
    /// <summary>An at-prefixed reference or raw-payload prefix; semantic interpretation is deferred.</summary>
    AtReference,
    /// <summary>One punctuation character or a recognized two-character operator.</summary>
    Symbol,
    /// <summary>A hash comment excluding its terminating line ending.</summary>
    Comment,
    /// <summary>A contiguous run of horizontal whitespace.</summary>
    Whitespace,
    /// <summary>An exact LF, CRLF or CR physical line ending.</summary>
    NewLine,
    /// <summary>A non-quoted backslash followed immediately by a physical line ending.</summary>
    Continuation,
    /// <summary>An initial Unicode byte-order marker retained in the original text.</summary>
    ByteOrderMark,
}

/// <summary>A source position measured in UTF-16 code units, with one-based physical line and column.</summary>
/// <param name="Offset">Zero-based offset into the original .NET string; not a UTF-8 byte offset.</param>
/// <param name="Length">Exact span length including any delimiters, in UTF-16 code units.</param>
/// <param name="Line">One-based physical source line at the span start.</param>
/// <param name="Column">One-based UTF-16 column at the span start; tabs count as one code unit.</param>
public readonly record struct NativeSourceSpan(int Offset, int Length, int Line, int Column);

/// <summary>An immutable category and position without a copied source value.</summary>
public sealed class NativeSourceToken
{
    internal NativeSourceToken(NativeSourceTokenKind kind, NativeSourceSpan span) { Kind = kind; Span = span; }

    /// <summary>Gets the lexical category; semantic support is determined separately.</summary>
    public NativeSourceTokenKind Kind { get; }
    /// <summary>Gets the exact position in the owning document.</summary>
    public NativeSourceSpan Span { get; }
    /// <summary>Gets whether this token is non-semantic whitespace, comment, BOM or a line continuation.</summary>
    /// <remarks>NewLine is significant as a statement boundary and is not trivia.</remarks>
    public bool IsTrivia => Kind is NativeSourceTokenKind.Whitespace or NativeSourceTokenKind.Comment or
        NativeSourceTokenKind.Continuation or NativeSourceTokenKind.ByteOrderMark;
    /// <summary>Returns category and position only, never private source text.</summary>
    public override string ToString() => $"{Kind} at {Span.Line}:{Span.Column}";
}

/// <summary>An immutable complete source and token spans covering it exactly; not a native syntax tree or policy.</summary>
public sealed class NativeSourceDocument
{
    internal NativeSourceDocument(string source, IEnumerable<NativeSourceToken> tokens)
    { Source = source; Tokens = Array.AsReadOnly(tokens.ToArray()); }

    /// <summary>Gets the exact potentially private original string, without normalization.</summary>
    public string Source { get; }
    /// <summary>Gets every token, including trivia, in original source order.</summary>
    public IReadOnlyList<NativeSourceToken> Tokens { get; }
    /// <summary>Reads the exact original text for a token index; callers must keep private values out of logs.</summary>
    /// <exception cref="ArgumentOutOfRangeException">The token index is outside this document.</exception>
    public string GetText(int tokenIndex)
    {
        if (tokenIndex < 0 || tokenIndex >= Tokens.Count) { throw new ArgumentOutOfRangeException(nameof(tokenIndex)); }
        var span = Tokens[tokenIndex].Span;
        return Source.Substring(span.Offset, span.Length);
    }

    /// <summary>Returns a token count only, never source contents.</summary>
    public override string ToString() => $"Native source ({Tokens.Count} tokens)";
}

/// <summary>A stable value-free lexical failure and its source position; not an nft diagnostic.</summary>
public sealed record NativeSourceLexicalDiagnostic(string Code, NativeSourceSpan Span);

/// <summary>A complete lexical document or one stable failure, never a partially tokenized document.</summary>
public sealed class NativeSourceLexingResult
{
    internal NativeSourceLexingResult(NativeSourceDocument? document, NativeSourceLexicalDiagnostic? diagnostic)
    { Document = document; Diagnostic = diagnostic; }

    /// <summary>Gets the complete document on success; null on any failure.</summary>
    public NativeSourceDocument? Document { get; }
    /// <summary>Gets the value-free failure, or null on success.</summary>
    public NativeSourceLexicalDiagnostic? Diagnostic { get; }
    /// <summary>Gets whether bounded tokenization completed; does not establish native syntax or conversion support.</summary>
    public bool IsComplete => Document is not null;
}

/// <summary>Retains bounded native source tokens and exact physical positions without interpretation or host access.</summary>
/// <remarks>Unknown tokens are retained. Success cannot authorize conversion, include resolution or execution.</remarks>
public static class NativeSourceLexer
{
    /// <summary>Maximum strict UTF-8 source bytes, matching the immutable source library bound.</summary>
    public const int MaximumBytes = 524_288;
    /// <summary>Maximum non-trivia, non-newline tokens; line endings remain represented in the complete document.</summary>
    public const int MaximumSignificantTokens = 65_536;
    /// <summary>Maximum total tokens including whitespace, comments, continuations, BOM and line endings.</summary>
    public const int MaximumTokens = 131_072;

    /// <summary>Tokenizes exact input with bounded work; failures contain positions and codes only.</summary>
    /// <exception cref="ArgumentNullException">Source is null.</exception>
    public static NativeSourceLexingResult Lex(string source)
    {
        ArgumentNullException.ThrowIfNull(source);
        try
        {
            if (source.Length > MaximumBytes || new UTF8Encoding(false, true).GetByteCount(source) > MaximumBytes)
            { return Failure("source.tooLarge", new(0, 0, 1, 1)); }
        }
        catch (EncoderFallbackException) { return Failure("source.invalidEncoding", new(0, 0, 1, 1)); }
        var tokens = new List<NativeSourceToken>();
        var index = 0; var line = 1; var column = 1; var significant = 0;
        while (index < source.Length)
        {
            var start = index; var startLine = line; var startColumn = column;
            var character = source[index];
            NativeSourceTokenKind kind;
            if (character == '\ufeff' && index == 0) { kind = NativeSourceTokenKind.ByteOrderMark; Advance(); }
            else if (IsDisallowedControl(character)) { return Failure("source.invalidCharacter", new(index, 1, line, column)); }
            else if (IsNewLine(character)) { kind = NativeSourceTokenKind.NewLine; Advance(); }
            else if (IsHorizontalWhitespace(character))
            {
                kind = NativeSourceTokenKind.Whitespace;
                do { Advance(); } while (index < source.Length && IsHorizontalWhitespace(source[index]));
            }
            else if (character == '#')
            {
                kind = NativeSourceTokenKind.Comment;
                do
                {
                    if (IsDisallowedControl(source[index])) { return Failure("source.invalidCharacter", new(index, 1, line, column)); }
                    Advance();
                } while (index < source.Length && !IsNewLine(source[index]));
            }
            else if (character is '"' or '\'')
            {
                kind = character == '"' ? NativeSourceTokenKind.DoubleQuoted : NativeSourceTokenKind.SingleQuoted;
                Advance(); var closed = false;
                while (index < source.Length)
                {
                    var next = source[index];
                    if (IsDisallowedControl(next)) { return Failure("source.invalidCharacter", new(index, 1, line, column)); }
                    Advance();
                    if (next == character) { closed = true; break; }
                    if (next == '\\' && index < source.Length)
                    {
                        if (IsDisallowedControl(source[index])) { return Failure("source.invalidCharacter", new(index, 1, line, column)); }
                        Advance();
                    }
                }
                if (!closed) { return Failure("source.unterminatedString", new(start, index - start, startLine, startColumn)); }
            }
            else if (character == '\\' && index + 1 < source.Length && IsNewLine(source[index + 1]))
            { kind = NativeSourceTokenKind.Continuation; Advance(); Advance(); }
            else if (IsSymbol(character))
            {
                kind = NativeSourceTokenKind.Symbol;
                Advance();
                if ((character is '$' or '@') && index < source.Length && !IsAtomBoundary(source, index))
                {
                    kind = character == '$' ? NativeSourceTokenKind.VariableReference : NativeSourceTokenKind.AtReference;
                    do { Advance(); } while (index < source.Length && !IsAtomBoundary(source, index));
                }
                else if (index < source.Length && IsPair(character, source[index])) { Advance(); }
            }
            else
            {
                kind = NativeSourceTokenKind.Bare;
                do { Advance(); } while (index < source.Length && !IsAtomBoundary(source, index));
            }
            var token = new NativeSourceToken(kind, new(start, index - start, startLine, startColumn));
            if (tokens.Count == MaximumTokens || (!token.IsTrivia && kind != NativeSourceTokenKind.NewLine && ++significant > MaximumSignificantTokens))
            { return Failure("source.tooManyTokens", token.Span); }
            tokens.Add(token);
        }
        return new(new(source, tokens), null);

        void Advance()
        {
            if (source[index] == '\r')
            {
                index++;
                if (index < source.Length && source[index] == '\n') { index++; }
                line++; column = 1;
            }
            else if (source[index] == '\n') { index++; line++; column = 1; }
            else { index++; column++; }
        }
    }

    private static bool IsNewLine(char value) => value is '\r' or '\n';
    private static bool IsHorizontalWhitespace(char value) => value is ' ' or '\t';
    private static bool IsAtomBoundary(string source, int index) => IsBoundary(source[index]) ||
        (source[index] == '\\' && index + 1 < source.Length && IsNewLine(source[index + 1]));
    private static bool IsDisallowedControl(char value) => char.IsControl(value) && value is not ('\r' or '\n' or '\t');
    private static bool IsBoundary(char value) => IsHorizontalWhitespace(value) || IsNewLine(value) || IsDisallowedControl(value) || value is '#' or '"' or '\'' || IsSymbol(value);
    private static bool IsSymbol(char value) => value is '{' or '}' or '[' or ']' or '(' or ')' or ';' or ',' or '=' or '!' or '<' or '>' or '&' or '|' or '^' or '$' or '@';
    private static bool IsPair(char first, char second) => (first, second) is ('!', '=') or ('=', '=') or ('<', '=') or ('>', '=') or ('<', '<') or ('>', '>') or ('&', '&') or ('|', '|');
    private static NativeSourceLexingResult Failure(string code, NativeSourceSpan span) => new(null, new(code, span));
}
