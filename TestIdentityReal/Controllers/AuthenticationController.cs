using Google.Apis.Auth;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using TestIdentityReal.DTO;
using TestIdentityReal.Entity;
using TestIdentityReal.Helper;
using static System.Net.WebRequestMethods;

namespace TestIdentityReal.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly ILogger<WeatherForecastController> _logger;
        private readonly UserManager<AppUser> _userManager;
        private readonly ITokenHelper _tokenHelper;
        private readonly IConfiguration _configuration;
        private readonly IEmailSender _emailSender;
        public string frontendurl = "hehe";
        public AuthenticationController(ILogger<WeatherForecastController> logger, UserManager<AppUser> userManager, ITokenHelper tokenHelper, IConfiguration configuration, IEmailSender emailSender)
        {
            _logger = logger;
            _userManager = userManager;
            _tokenHelper = tokenHelper;
            _configuration = configuration;
            _emailSender = emailSender;
        }

        //[HttpPost("register")]
        //public async Task<IActionResult> Register([FromBody] RegisterDto model)
        //{
        //    if (!ModelState.IsValid) return BadRequest(ModelState);

        //    var user = new AppUser { UserName = model.Email, Email = model.Email,PhoneNumber = model.PhoneNumber,FullName = model.FullName };
        //    var result = await _userManager.CreateAsync(user, model.Password);

        //    if (result.Succeeded)
        //    {
        //        var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
        //        var confirmationLink = $"{frontendurl}/confirm-email?userId={user.Id}&token={Uri.EscapeDataString(token)}";

        //        await _emailSender.SendEmailAsync(user.Email, "Confirm your email", $"Click <a href='{confirmationLink}'>here</a> to confirm your email.");

        //        return Ok(new { Message = "Registration successful. Check your email to confirm your account." });
        //    }

        //    return BadRequest(result.Errors);
        //}
        //[HttpPost("testmail")]
        //public async Task<IActionResult> testmail([FromBody] string email)
        //{
        //    await _emailSender.SendEmailAsync(email, "Confirm your email", $"Click <a href='{"https://www.youtube.com/watch?v=pxwm3sqAytE"}'>here</a> to confirm your email.");
        //    return Ok();
        //}

        //[HttpGet("confirm-email")]
        //public async Task<IActionResult> ConfirmEmail(string userId, string token)
        //{
        //    var user = await _userManager.FindByIdAsync(userId);
        //    if (user == null) return BadRequest("Invalid user.");

        //    var result = await _userManager.ConfirmEmailAsync(user, token);
        //    if (!result.Succeeded) return BadRequest("Email confirmation failed.");

        //    return Ok("Email confirmed successfully.");
        //}
        //[HttpPost("login")]
        //public async Task<IActionResult> Login([FromBody] LoginDto model)
        //{
        //    var user = await _userManager.FindByEmailAsync(model.Email);
        //    if (user == null || !await _userManager.CheckPasswordAsync(user, model.Password))
        //        return Unauthorized("Invalid credentials.");

        //    if (!await _userManager.IsEmailConfirmedAsync(user))
        //        return Unauthorized("Email not confirmed.");

        //    var roles = await _userManager.GetRolesAsync(user);
        //    var role = await _userManager.GetRolesAsync(user);

        //    var accessToken = _tokenHelper.GenerateJwtToken(user, role.FirstOrDefault());
        //    var refreshToken = await _tokenHelper.GenerateRefreshToken(user);

        //    return Ok(new { AccessToken = accessToken, RefreshToken = refreshToken });
        //}

        //[HttpPost("signin-google")]
        //public async Task<IActionResult> GoogleLogin([FromBody] GoogleLoginDto model)
        //{
        //    var settings = new GoogleJsonWebSignature.ValidationSettings()
        //    {
        //        Audience = new List<string> { _configuration["GoogleAuth:ClientId"] }
        //    };

        //    GoogleJsonWebSignature.Payload payload;
        //    try
        //    {
        //        payload = await GoogleJsonWebSignature.ValidateAsync(model.IdToken, settings);
        //    }
        //    catch (Exception)
        //    {
        //        return Unauthorized(new { message = "Invalid Google token" });
        //    }

        //    var user = await _userManager.FindByEmailAsync(payload.Email);
        //    if (user == null)
        //    {
        //        user = new AppUser
        //        {
        //            UserName = payload.Name,
        //            Email = payload.Email,
        //            FullName = payload.Name,
        //        };

        //        var result = await _userManager.CreateAsync(user);
        //        if (!result.Succeeded)
        //            return BadRequest(result.Errors);

        //        await _userManager.AddToRoleAsync(user, "Customer"); 
        //    }

        //    var role = (await _userManager.GetRolesAsync(user)).FirstOrDefault();
        //    var accessToken = _tokenHelper.GenerateJwtToken(user, role);
        //    var refreshToken = await _tokenHelper.GenerateRefreshToken(user);

        //    return Ok(new { AccessToken = accessToken, RefreshToken = refreshToken });
        //}

        //[HttpPost("refresh-token")]
        //public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenDto model)
        //{
        //    var principal = _tokenHelper.GetPrincipalFromExpiredToken(model.Token);
        //    if (principal == null)
        //        return Unauthorized(new { Message = "Invalid token" });

        //    var userId = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        //    if (string.IsNullOrEmpty(userId))
        //        return Unauthorized(new { Message = "Invalid token claims" });

        //    var user = await _userManager.FindByIdAsync(userId);
        //    if (user == null)
        //        return Unauthorized(new { Message = "User not found" });

        //    var storedRefreshToken = await _userManager.GetAuthenticationTokenAsync(user, "MyApp", "RefreshToken");
        //    if (storedRefreshToken != model.RefreshToken)
        //        return Unauthorized(new { Message = "Invalid refresh token" });

        //    var roles = await _userManager.GetRolesAsync(user);
        //    var newAccessToken = _tokenHelper.GenerateJwtToken(user, roles.FirstOrDefault());
        //    var newRefreshToken = await _tokenHelper.GenerateRefreshToken(user);

        //    return Ok(new { Token = newAccessToken, RefreshToken = newRefreshToken });
        //}
        //[HttpPost("TestClaim")]
        //public async Task<IActionResult> TestClaim([FromBody] RefreshTokenDto1 model)
        //{
        //    var principal = _tokenHelper.GetPrincipalFromExpiredToken(model.Token);
        //    var userId = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        //    return Ok(userId);
        //}

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDto model)
        {
            if (!ModelState.IsValid)
                return BadRequest(new AppResponse<object>().SetErrorResponse("ModelState", ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage).ToArray()));

            var user = new AppUser { UserName = model.Email, Email = model.Email, PhoneNumber = model.PhoneNumber, FullName = model.FullName };
            var result = await _userManager.CreateAsync(user, model.Password);

            if (result.Succeeded)
            {
                await _userManager.AddToRoleAsync(user, "Customer");
                var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                var confirmationLink = $"{frontendurl}/confirm-email?userId={user.Id}&token={Uri.EscapeDataString(token)}";

                await _emailSender.SendEmailAsync(user.Email, "Confirm your email", $"Click <a href='{confirmationLink}'>here</a> to confirm your email.");

                return Ok(new AppResponse<object>().SetSuccessResponse(null, "Message", "Registration successful. Check your email to confirm your account."));
            }

            return BadRequest(new AppResponse<object>().SetErrorResponse("IdentityErrors", result.Errors.Select(e => e.Description).ToArray()));
        }
        //[HttpPost("register-housekeeper")]
        //public async Task<IActionResult> Register1([FromBody] RegisterHousekeeperDto model)
        //{
        //    if (!ModelState.IsValid)
        //        return BadRequest(new AppResponse<object>().SetErrorResponse("ModelState", ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage).ToArray()));

        //    var user = new AppUser { UserName = model.Email, Email = model.Email,
        //        PhoneNumber = model.PhoneNumber, FullName = model.FullName, PDF = model.Pdf, Avatar = model.Avatar
        //    };
        //    var result = await _userManager.CreateAsync(user, model.Password);

        //    if (result.Succeeded)
        //    {

        //        return Ok(new AppResponse<object>().SetSuccessResponse(null, "Message", "Registration successful. Wait for staff to confirm your shit."));
        //    }

        //    return BadRequest(new AppResponse<object>().SetErrorResponse("IdentityErrors", result.Errors.Select(e => e.Description).ToArray()));
        //}
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDto model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null || !await _userManager.CheckPasswordAsync(user, model.Password))
                return Unauthorized(new AppResponse<object>().SetErrorResponse("Credentials", "Invalid credentials."));

            if (!await _userManager.IsEmailConfirmedAsync(user))
                return Unauthorized(new AppResponse<object>().SetErrorResponse("Email", "Email not confirmed."));

            var roles = await _userManager.GetRolesAsync(user);
            var role = roles.FirstOrDefault();

            var accessToken = _tokenHelper.GenerateJwtToken(user, role);
            var refreshToken = await _tokenHelper.GenerateRefreshToken(user);

            return Ok(new AppResponse<object>().SetSuccessResponse(new { AccessToken = accessToken, RefreshToken = refreshToken }));
        }
        [HttpGet("confirm-email")]
        public async Task<IActionResult> ConfirmEmail(string userId, string token)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return BadRequest(new AppResponse<object>().SetErrorResponse("User", "Invalid user."));

            var result = await _userManager.ConfirmEmailAsync(user, token);
            if (!result.Succeeded)
                return BadRequest(new AppResponse<object>().SetErrorResponse("EmailConfirmation", "Email confirmation failed."));

            return Ok(new AppResponse<object>().SetSuccessResponse(null, "Message", "Email confirmed successfully."));
        }
        [HttpPost("signin-google")]
        public async Task<IActionResult> GoogleLogin([FromBody] GoogleLoginDto model)
        {
            var settings = new GoogleJsonWebSignature.ValidationSettings()
            {
                Audience = new List<string> { _configuration["GoogleAuth:ClientId"] }
            };

            GoogleJsonWebSignature.Payload payload;
            try
            {
                payload = await GoogleJsonWebSignature.ValidateAsync(model.IdToken, settings);
            }
            catch (Exception)
            {
                return Unauthorized(new AppResponse<object>().SetErrorResponse("GoogleAuth", "Invalid Google token."));
            }

            var user = await _userManager.FindByEmailAsync(payload.Email);
            if (user == null)
            {
                user = new AppUser
                {
                    UserName = payload.Name,
                    Email = payload.Email,
                    FullName = payload.Name,
                };

                var result = await _userManager.CreateAsync(user);
                if (!result.Succeeded)
                    return BadRequest(new AppResponse<object>().SetErrorResponse("IdentityErrors", result.Errors.Select(e => e.Description).ToArray()));

                await _userManager.AddToRoleAsync(user, "Customer");
            }

            var role = (await _userManager.GetRolesAsync(user)).FirstOrDefault();
            var accessToken = _tokenHelper.GenerateJwtToken(user, role);
            var refreshToken = await _tokenHelper.GenerateRefreshToken(user);

            return Ok(new AppResponse<object>().SetSuccessResponse(new { AccessToken = accessToken, RefreshToken = refreshToken }));
        }
        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenDto model)
        {
            var principal = _tokenHelper.GetPrincipalFromExpiredToken(model.Token);
            if (principal == null)
                return Unauthorized(new AppResponse<object>().SetErrorResponse("Token", "Invalid token."));

            var userId = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userId))
                return Unauthorized(new AppResponse<object>().SetErrorResponse("Token", "Invalid token claims."));

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return Unauthorized(new AppResponse<object>().SetErrorResponse("User", "User not found."));

            var storedRefreshToken = await _userManager.GetAuthenticationTokenAsync(user, "MyApp", "RefreshToken");
            if (storedRefreshToken != model.RefreshToken)
                return Unauthorized(new AppResponse<object>().SetErrorResponse("Token", "Invalid refresh token."));

            var roles = await _userManager.GetRolesAsync(user);
            var newAccessToken = _tokenHelper.GenerateJwtToken(user, roles.FirstOrDefault());
            var newRefreshToken = await _tokenHelper.GenerateRefreshToken(user);

            return Ok(new AppResponse<object>().SetSuccessResponse(new { Token = newAccessToken, RefreshToken = newRefreshToken }));
        }
        [HttpPost("testmail")]
        public async Task<IActionResult> TestMail([FromBody] string email)
        {
            await _emailSender.SendEmailAsync(email, "Confirm your email", $"Click <a href='https://www.youtube.com/watch?v=pxwm3sqAytE'>here</a> to confirm your email.");

            return Ok(new AppResponse<object>().SetSuccessResponse(null, "Message", "Test email sent successfully."));
        }
        [HttpPost("TestClaim")]
        public async Task<IActionResult> TestClaim([FromBody] RefreshTokenDto1 model)
        {
            var principal = _tokenHelper.GetPrincipalFromExpiredToken(model.Token);
            var userId = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;

            return Ok(new AppResponse<object>().SetSuccessResponse(new { UserId = userId }));
        }


    }
}

