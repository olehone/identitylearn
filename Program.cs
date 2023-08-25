
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc;

const string AuthScheme = "cookie";
var builder = WebApplication.CreateBuilder(args);
builder.Services.AddDataProtection();
builder.Services.AddHttpContextAccessor();
builder.Services.AddAuthentication(AuthScheme).AddCookie(AuthScheme);

/*
builder.Services.AddScoped<AuthService>();
*/
var app = builder.Build();
app.UseAuthentication();

/*
app.Use((ctx, next) =>
{
    var idp = ctx.RequestServices.GetRequiredService<IDataProtectionProvider>();
    var protector = idp.CreateProtector("auth-cookie");

    string? authCookie = ctx.Request.Headers.Cookie.FirstOrDefault(x => x.StartsWith("auth="));
    var protectedPayload = authCookie.Split("=").Last();
    var payload = protector.Unprotect(protectedPayload);

    string[] parts = payload.Split(":");
    string key = parts[0];
    string value = parts[1];
    var claims = new List<Claim>();
    claims.Add(new Claim(key,value));
    var identity = new ClaimsIdentity(claims);
    ctx.User = new ClaimsPrincipal(identity);
    return next();
});
*/

app.MapGet("/username", (HttpContext ctx ) =>
{
    return ctx.User.FindFirst("user")?.Value ?? "no user";
});

app.MapGet("/admin", (HttpContext ctx ) =>
{
    if (!ctx.User.Identities.Any(x => x.AuthenticationType == AuthScheme))
    {
        ctx.Response.StatusCode = 401;
        return "";
    }

    if (!ctx.User.HasClaim("access", "admin"))
    {
        ctx.Response.StatusCode = 403;
        return "";
    }
    return "ok, u are admin, let`s ban someone";
});

app.MapGet("/logout",async (HttpContext ctx) =>
{
    await ctx.SignOutAsync(AuthScheme);
    return "logout successfull";
});
app.MapGet("/login",async (HttpContext ctx) =>
{
    var claims = new List<Claim>();
    claims.Add(new Claim("user","oleh"));
    claims.Add(new Claim("access","admin"));
    var identity = new ClaimsIdentity(claims, "cookie");
    var user = new ClaimsPrincipal(identity);
    await ctx.SignInAsync("cookie", user);
    return "ok";
});


app.Run();

/*
public class AuthService
{
    private readonly IDataProtectionProvider _idp;
    private readonly IHttpContextAccessor _accessor;

    public AuthService(IDataProtectionProvider idp, IHttpContextAccessor accessor)
    {
        _idp = idp;
        _accessor = accessor;
    }

    public void SingIn()
    {
        var protector = _idp.CreateProtector("auth-cookie");
        _accessor.HttpContext.Response.Headers["set-cookie"] = $"auth={protector.Protect("usr:anton")}";
    }

}*/