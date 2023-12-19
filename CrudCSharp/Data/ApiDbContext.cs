using CrudCSharp.Model;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;


namespace CrudCSharp.Data
{
    public class ApiDbContext : IdentityDbContext
    {
        public ApiDbContext(DbContextOptions<ApiDbContext> options) : base(options) 
        {
        }

        public DbSet<Produto> Produtos { get; set; } //criando tabela com as propriedades da classe Produto


    }
}
