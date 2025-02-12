﻿using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Diagnostics;
using System.Security.Claims;
using TestIdentityReal.Data;
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
        public string frontendurl;

        public AuthenticationController(ILogger<WeatherForecastController> logger, UserManager<AppUser> userManager, ITokenHelper tokenHelper, IConfiguration configuration, IEmailSender emailSender)
        {
            _logger = logger;
            _userManager = userManager;
            _tokenHelper = tokenHelper;
            _configuration = configuration;
            _emailSender = emailSender;
            frontendurl = configuration["Url:Frontend"] ?? "https://www.youtube.com/";
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

            var user = new AppUser {UserName = model.Email,Email = model.Email, PhoneNumber = model.PhoneNumber, FullName = model.FullName };
            var result = await _userManager.CreateAsync(user, model.Password);

            if (result.Succeeded)
            {
                await _userManager.AddToRoleAsync(user, "Customer");
                var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                var confirmationLink = $"{frontendurl}/confirm-email?userId={user.Id}&token={Uri.EscapeDataString(token)}";

                await _emailSender.SendEmailAsync(user.Email, "Confirm your email", $"Click <a href='{confirmationLink}'>here</a> to confirm your email.");

                return Ok(new AppResponse<object>().SetSuccessResponse(null!, "Message", "Registration successful. Check your email to confirm your account."));
            }
            var identityErrors = result.Errors
            .Where(e => e.Code != "DuplicateUserName")
            .GroupBy(e => e.Code)
            .ToDictionary(
                g => g.Key,
                g => g.Select(e => e.Description).ToArray()
            );
            return BadRequest(new AppResponse<object>().SetErrorResponse(identityErrors));

        }
        //[HttpPost("registerTest")]
        //public async Task<IActionResult> Register1([FromBody] RegisterDto model)
        //{
        //    var stopwatch = Stopwatch.StartNew();

        //    if (!ModelState.IsValid)
        //    {
        //        return BadRequest(new AppResponse<object>().SetErrorResponse("ModelState", ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage).ToArray()));
        //    }

        //    stopwatch.Stop();
        //    Console.WriteLine($"[INFO] Model validation took: {stopwatch.ElapsedMilliseconds} ms");

        //    stopwatch.Restart();
        //    var user = new AppUser { UserName = model.Email, Email = model.Email, PhoneNumber = model.PhoneNumber, FullName = model.FullName };
        //    var result = await _userManager.CreateAsync(user, model.Password);
        //    stopwatch.Stop();
        //    Console.WriteLine($"[INFO] Creating user took: {stopwatch.ElapsedMilliseconds} ms");

        //    if (result.Succeeded)
        //    {
        //        stopwatch.Restart();
        //        var customerRole = await _roleManager.FindByNameAsync("Customer");
        //        if (customerRole != null)
        //        {
        //            var userRole = new IdentityUserRole<string> { UserId = user.Id, RoleId = customerRole.Id };

        //        }
        //        stopwatch.Stop();
        //        Console.WriteLine($"[INFO] Assigning role took: {stopwatch.ElapsedMilliseconds} ms");

        //        stopwatch.Restart();
        //        var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
        //        stopwatch.Stop();
        //        Console.WriteLine($"[INFO] Generating token took: {stopwatch.ElapsedMilliseconds} ms");

        //        stopwatch.Restart();
        //        var confirmationLink = $"{frontendurl}/confirm-email?userId={user.Id}&token={Uri.EscapeDataString(token)}";
        //        await _emailSender.SendEmailAsync(user.Email, "Confirm your email", $"Click <a href='{confirmationLink}'>here</a> to confirm your email.");
        //        stopwatch.Stop();
        //        Console.WriteLine($"[INFO] Sending email took: {stopwatch.ElapsedMilliseconds} ms");

        //        Console.WriteLine($"[INFO] Total registration time: {stopwatch.ElapsedMilliseconds} ms");

        //        return Ok(new AppResponse<object>().SetSuccessResponse(null!, "Message", "Registration successful. Check your email to confirm your account."));
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

            var accessToken = _tokenHelper.GenerateJwtToken(user, role!);
            var refreshToken = await _tokenHelper.GenerateRefreshToken(user);

            return Ok(new AppResponse<object>().SetSuccessResponse(new { AccessToken = accessToken, RefreshToken = refreshToken}));
        }
        [HttpPost("loginTest")]
        public async Task<IActionResult> Login1([FromBody] LoginDto model)
        {
            model.Email = "customer1@example.com";
            model.Password = "123"; 
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null || !await _userManager.CheckPasswordAsync(user, model.Password))
                return Unauthorized(new AppResponse<object>().SetErrorResponse("Credentials", "Invalid credentials."));

            if (!await _userManager.IsEmailConfirmedAsync(user))
                return Unauthorized(new AppResponse<object>().SetErrorResponse("Email", "Email not confirmed."));

            var roles = await _userManager.GetRolesAsync(user);
            var role = roles.FirstOrDefault();

            var accessToken = _tokenHelper.GenerateJwtToken(user, role!);
            var refreshToken = await _tokenHelper.GenerateRefreshToken(user);

            return Ok(new AppResponse<object>().SetSuccessResponse(new { AccessToken = accessToken, RefreshToken = refreshToken}));
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

            return Ok(new AppResponse<object>().SetSuccessResponse(null!, "Message", "Email confirmed successfully."));
        }
        //[HttpPost("signin-google")]
        //public async Task<IActionResult> GoogleLogin([FromBody] GoogleLoginDto model)
        //{
        //    var settings = new GoogleJsonWebSignature.ValidationSettings()
        //    {
        //        Audience = new List<string> { _configuration["GoogleAuth:ClientId"]! }
        //    };

        //    GoogleJsonWebSignature.Payload payload;
        //    try
        //    {
        //        payload = await GoogleJsonWebSignature.ValidateAsync(model.IdToken, settings);
        //    }
        //    catch (Exception)
        //    {
        //        return Unauthorized(new AppResponse<object>().SetErrorResponse("GoogleAuth", "Invalid Google token."));
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
        //            return BadRequest(new AppResponse<object>().SetErrorResponse("IdentityErrors", result.Errors.Select(e => e.Description).ToArray()));

        //        await _userManager.AddToRoleAsync(user, "Customer");
        //    }

        //    var role = (await _userManager.GetRolesAsync(user)).FirstOrDefault();
        //    var accessToken = _tokenHelper.GenerateJwtToken(user, role!);
        //    var refreshToken = await _tokenHelper.GenerateRefreshToken(user);

        //    return Ok(new AppResponse<object>().SetSuccessResponse(new { AccessToken = accessToken, RefreshToken = refreshToken, Role = role }));
        //}
        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenDto model)
        {
            var principal = _tokenHelper.GetPrincipalFromExpiredToken(model.Token);
            if (principal == null)
                return Unauthorized(new AppResponse<object>().SetErrorResponse("Token", "Invalid token."));

            var userId = principal.FindFirst("id")?.Value;
            if (string.IsNullOrEmpty(userId))
                return Unauthorized(new AppResponse<object>().SetErrorResponse("Token", "Invalid token claims."));

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return Unauthorized(new AppResponse<object>().SetErrorResponse("User", "User not found."));

            var storedRefreshToken = await _userManager.GetAuthenticationTokenAsync(user, "MyApp", "RefreshToken");
            if (storedRefreshToken != model.RefreshToken)
                return Unauthorized(new AppResponse<object>().SetErrorResponse("Token", "Invalid refresh token."));

            var roles = await _userManager.GetRolesAsync(user);
            var role = roles.FirstOrDefault();
            var newAccessToken = _tokenHelper.GenerateJwtToken(user, role!);
            var newRefreshToken = await _tokenHelper.GenerateRefreshToken(user);

            return Ok(new AppResponse<object>().SetSuccessResponse(new { AccessToken = newAccessToken, RefreshToken = newRefreshToken }));
        }
        [HttpPost("resend-confirmation")]
        public async Task<IActionResult> ResendConfirmationEmail([FromBody] ResendConfirmationDto model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
                return BadRequest(new AppResponse<object>().SetErrorResponse("Email", "User not found."));

            if (await _userManager.IsEmailConfirmedAsync(user))
                return BadRequest(new AppResponse<object>().SetErrorResponse("Email", "Email already confirmed."));

            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            var confirmationLink = $"{frontendurl}/confirm-email?userId={user.Id}&token={Uri.EscapeDataString(token)}";

            await _emailSender.SendEmailAsync(user.Email!, "Confirm your email",
                $"Click <a href='{confirmationLink}'>here</a> to confirm your email.");

            return Ok(new AppResponse<object>().SetSuccessResponse(null!, "Message", "Confirmation email resent successfully."));
        }
        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordDto model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
                return BadRequest(new AppResponse<object>().SetErrorResponse("Email", "User not found."));

            var result = await _userManager.ResetPasswordAsync(user, model.Token, model.NewPassword);
            if (!result.Succeeded)
                return BadRequest(new AppResponse<object>().SetErrorResponse("IdentityErrors", result.Errors.Select(e => e.Description).ToArray()));

            return Ok(new AppResponse<object>().SetSuccessResponse(null!, "Message", "Password reset successful."));
        }
        [HttpPost("forgot-password")]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordDto model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
                return BadRequest(new AppResponse<object>().SetErrorResponse("Email", "User not found."));

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var resetLink = $"{frontendurl}/reset-password?email={Uri.EscapeDataString(user.Email!)}&token={Uri.EscapeDataString(token)}";

            await _emailSender.SendEmailAsync(user.Email!, "Reset Password", $"Click <a href='{resetLink}'>here</a> to reset your password.");

            return Ok(new AppResponse<object>().SetSuccessResponse(null!, "Message", "Password reset link sent to your email."));
        }
        [HttpPost("testmail")]
        public async Task<IActionResult> TestMail([FromBody] string email)
        {
            await _emailSender.SendEmailAsync(email, "Confirm your email", $"Click <a href='https://www.youtube.com/watch?v=pxwm3sqAytE'>here</a> to confirm your email.");

            return Ok(new AppResponse<object>().SetSuccessResponse(null!, "Message", "Test email sent successfully."));
        }


    }
}

