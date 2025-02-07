using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using TestIdentityReal.Entity;
using TestIdentityReal.Service;

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
        private readonly ITokenHelper _tokenHelper;
        private readonly IFileService _fileService;
        private readonly BlobStorageService _blobStorageService;

        public WeatherForecastController(ILogger<WeatherForecastController> logger, UserManager<AppUser> userManager, ITokenHelper tokenHelper, IFileService fileService, BlobStorageService blobStorageService)
        {
            _logger = logger;
            _userManager = userManager;
            _tokenHelper = tokenHelper;
            _fileService = fileService;
            _blobStorageService = blobStorageService;
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
        [HttpGet("file")]
        public IActionResult TestFile(string file)
        {
            return Ok("hehe");
        }
        [HttpPost("upload")]
        [Consumes("multipart/form-data")] // Required for file uploads in Swagger
        public async Task<IActionResult> UploadBlob(IFormFile file)
        {
            if (file == null || file.Length == 0)
            {
                return BadRequest("File is required.");
            }

            var fileUrl = await _fileService.Upload(file);
            return Ok(new { FileUrl = fileUrl });
        }
        [HttpPost("upload123")]
        [Consumes("multipart/form-data")]
        public async Task<IActionResult> UploadFile(IFormFile file)
        {
            try
            {
                string fileUrl = await _blobStorageService.UploadFileAsync(file);
                return Ok(new { Url = fileUrl });
            }
            catch (Exception ex)
            {
                return BadRequest(new { Message = ex.Message });
            }
        }
        [HttpPost("uploadMultiple")]
        public async Task<IActionResult> UploadFiles([FromForm] List<IFormFile> files)
        {
            if (files == null || files.Count == 0)
            {
                return BadRequest("No files uploaded.");
            }
            foreach (var file in files)
            {
                if (file.Length > 5 * 1024 * 1024)
                {
                    return BadRequest($"File {file.FileName} exceeds the size limit of {5 * 1024 * 1024 / 1024 / 1024} MB.");
                }
            }

            try
            {
                var sasUrls = await _blobStorageService.UploadFilesAsync(files);
                return Ok(new { Message = "Files uploaded successfully!", Urls = sasUrls });
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"An error occurred while uploading files: {ex.Message}");
            }
        }
        [HttpGet("Ok")]
        public IActionResult testOk()
        {
            return Ok();
        }
        [HttpGet("Untho")]
        public IActionResult test401()
        {
            return Unauthorized("hehe");
        }
    }
}
