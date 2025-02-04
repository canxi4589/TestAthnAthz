using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using TestIdentityReal.Entity;

namespace TestIdentityReal.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class WeatherForecastController : ControllerBase
    {
        private static readonly string[] Summaries = new[]
        {
            "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
        };

        private readonly ILogger<WeatherForecastController> _logger;
        private readonly UserManager<AppUser> _userManager;
        private readonly TokenHelper _tokenHelper;

        public WeatherForecastController(ILogger<WeatherForecastController> logger, UserManager<AppUser> userManager, TokenHelper tokenHelper)
        {
            _logger = logger;
            _userManager = userManager;
            _tokenHelper = tokenHelper;
        }

        [HttpGet(Name = "GetWeatherForecast")]
        public IEnumerable<WeatherForecast> Get()
        {
            return Enumerable.Range(1, 5).Select(index => new WeatherForecast
            {
                Date = DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
                TemperatureC = Random.Shared.Next(-20, 55),
                Summary = Summaries[Random.Shared.Next(Summaries.Length)]
            })
            .ToArray();
        }
        [HttpPost(Name = "testLogin")]
        public async Task<IActionResult> testLogin([FromBody] string username)
        {
            var user =await _userManager.FindByNameAsync(username);
            if (user == null) return BadRequest("Bruh");
            
            var role = await _userManager.GetRolesAsync(user);
            
            if (role == null) return BadRequest(string.Empty);

            return Ok(_tokenHelper.GenerateJwtToken(user, role.FirstOrDefault()));

        }
        [Authorize(Roles = "Admin")]
        [HttpGet("admin-dashboard")]
        public IActionResult GetAdminDashboard()
        {
            return Ok(new { Message = "Welcome, Admin!" });
        }
        [Authorize(Roles = "Staff")]
        [HttpGet("staff-dashboard")]
        public IActionResult GetStaffDashboard()
        {
            return Ok(new { Message = "Welcome, Staff!" });
        }
        [Authorize]
        [HttpGet("guest-dashboard")]
        public IActionResult GetGuestDashboard()
        {
            return Ok(new { Message = "Welcome, Guest!" });
        }
    }
}
