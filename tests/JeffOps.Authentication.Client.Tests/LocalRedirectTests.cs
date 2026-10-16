using JeffOps.Authentication.Abstractions.Http;

namespace JeffOps.Authentication.Client.Tests;

public sealed class LocalRedirectTests
{
    [Theory]
    [InlineData("/")]
    [InlineData("/done")]
    [InlineData("/a/b?c=d#e")]
    public void Paths_on_this_site_are_local(string url) => LocalRedirect.IsLocal(url).ShouldBeTrue();

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("https://evil.test/")]
    [InlineData("//evil.test")]
    [InlineData("/\evil.test")]
    [InlineData("/\t/evil.test")]
    [InlineData("/\r\n/evil.test")]
    [InlineData("done")]
    public void Anything_a_browser_could_take_off_site_is_not(string? url)
    {
        LocalRedirect.IsLocal(url).ShouldBeFalse();
        LocalRedirect.OrRoot(url).ShouldBe("/");
    }
}
