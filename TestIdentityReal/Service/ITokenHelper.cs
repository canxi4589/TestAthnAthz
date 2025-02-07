using System.Security.Claims;
using TestIdentityReal.Entity;

public interface ITokenHelper
{
    string GenerateJwtToken(AppUser user, string role);
    Task<string> GenerateRefreshToken(AppUser user);
    ClaimsPrincipal? GetPrincipalFromExpiredToken(string token);
}