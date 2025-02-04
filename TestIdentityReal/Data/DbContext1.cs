using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using TestIdentityReal.Entity;

namespace TestIdentityReal.Data
{
    public class DbContext1 : IdentityDbContext<AppUser>
    {
        public DbContext1(DbContextOptions<DbContext1> options)
            : base(options) { }
        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
        }
    }
}
