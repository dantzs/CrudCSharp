using Microsoft.EntityFrameworkCore;

namespace CrudCSharp.Data
{
    public class ApiDbContext : DbContext
    {
        public ApiDbContext(DbContextOptions<ApiDbContext> options) : base(options) 
        {
        }


    }
}
