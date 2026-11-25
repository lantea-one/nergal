using Nergal.Identity;

namespace Nergal.Web.Tests;

/// <summary>Verifies credential input bounds without creating a socket or directory connection.</summary>
public sealed class LdapCredentialInputTests
{
    /// <summary>Allows exact Unicode credentials and preserves spaces.</summary>
    [Theory]
    [InlineData(" room key ")]
    [InlineData("clé de démonstration")]
    [InlineData(" ")]
    public void PasswordValidation_PreservesValidInput(string password)
    {
        Assert.True(LdapDirectoryAuthenticator.ValidPassword(password));
    }

    /// <summary>Denies empty, oversized, embedded-NUL and malformed Unicode credentials.</summary>
    [Fact]
    public void PasswordValidation_DeniesUnsafeInput()
    {
        Assert.False(LdapDirectoryAuthenticator.ValidPassword(null));
        Assert.False(LdapDirectoryAuthenticator.ValidPassword(""));
        Assert.False(LdapDirectoryAuthenticator.ValidPassword("word\0suffix"));
        Assert.False(LdapDirectoryAuthenticator.ValidPassword(new string('a', 2049)));
        Assert.False(LdapDirectoryAuthenticator.ValidPassword(new string('\ud800', 1)));
    }
}
