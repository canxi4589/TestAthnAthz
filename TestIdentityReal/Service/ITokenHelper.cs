using TestIdentityReal.Entity;

public interface ITokenHelper
{
    string GenerateJwtToken(AppUser user, string role);
    Task<string> GenerateRefreshToken(AppUser user);
}