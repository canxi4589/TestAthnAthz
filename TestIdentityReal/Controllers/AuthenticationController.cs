using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using TestIdentityReal.DTO;
using TestIdentityReal.Entity;
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

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDto model)
        {
            if (!ModelState.IsValid) return BadRequest(ModelState);

            var user = new AppUser { UserName = model.Email, Email = model.Email };
            var result = await _userManager.CreateAsync(user, model.Password);

            if (result.Succeeded)
            {
                var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                var confirmationLink = $"{frontendurl}/confirm-email?userId={user.Id}&token={Uri.EscapeDataString(token)}";

                await _emailSender.SendEmailAsync(user.Email, "Confirm your email", $"Click <a href='{confirmationLink}'>here</a> to confirm your email.");

                return Ok(new { Message = "Registration successful. Check your email to confirm your account." });
            }

            return BadRequest(result.Errors);
        }
        [HttpPost("mail")]
        public async Task<IActionResult> testmail([FromBody] string email)
        {
            await _emailSender.SendEmailAsync(email, "Confirm your email", $"Click <a href='{"https://www.youtube.com/watch?v=pxwm3sqAytE"}'>here</a> to confirm your email.");
            return Ok();
        }

        [HttpGet("confirm-email")]
        public async Task<IActionResult> ConfirmEmail(string userId, string token)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null) return BadRequest("Invalid user.");

            var result = await _userManager.ConfirmEmailAsync(user, token);
            if (!result.Succeeded) return BadRequest("Email confirmation failed.");

            return Ok("Email confirmed successfully.");
        }
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDto model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null || !await _userManager.CheckPasswordAsync(user, model.Password))
                return Unauthorized("Invalid credentials.");

            if (!await _userManager.IsEmailConfirmedAsync(user))
                return Unauthorized("Email not confirmed.");

            var roles = await _userManager.GetRolesAsync(user);
            var role = await _userManager.GetRolesAsync(user);

            var accessToken = _tokenHelper.GenerateJwtToken(user, role.FirstOrDefault());
            var refreshToken = await _tokenHelper.GenerateRefreshToken(user);

            return Ok(new { AccessToken = accessToken, RefreshToken = refreshToken });
        }
        //[HttpPost("refresh-token")]
        //public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenDto model)
        //{
        //    var principal = _tokenHelper.ge(model.Token);
        //    if (principal == null)
        //        return Unauthorized(new { Message = "Invalid token" });

        //    var user = await _userManager.FindByIdAsync(principal.FindFirst(ClaimTypes.NameIdentifier)?.Value);
        //    if (user == null)
        //        return Unauthorized(new { Message = "User not found" });

        //    var storedRefreshToken = await _userManager.GetAuthenticationTokenAsync(user, "MyApp", "RefreshToken");
        //    if (storedRefreshToken != model.RefreshToken)
        //        return Unauthorized(new { Message = "Invalid refresh token" });

        //    var roles = await _userManager.GetRolesAsync(user);z
        //    var newAccessToken = _tokenHelper.GenerateJwtToken(user, roles);
        //    var newRefreshToken = await GenerateRefreshToken(user);

        //    return Ok(new { Token = newAccessToken, RefreshToken = newRefreshToken });
        //}


        
    }
}

