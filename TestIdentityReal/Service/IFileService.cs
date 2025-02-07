
namespace TestIdentityReal.Service
{
    public interface IFileService
    {
        Task<string> Upload(IFormFile file);
    }
}