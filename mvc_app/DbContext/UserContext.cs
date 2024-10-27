using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace mvc_app.DbContext
{
    public class UserContext : IdentityDbContext
    {
        public UserContext(DbContextOptions<UserContext> options) 
            : base(options) { }
    }
}
