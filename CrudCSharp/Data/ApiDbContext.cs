using CrudCSharp.Model;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Internal;

namespace CrudCSharp.Data
{
    public class ApiDbContext : DbContext
    {
        public ApiDbContext(DbContextOptions<ApiDbContext> options) : base(options) 
        {
        }

        public DbSet<Produto> Produtos { get; set; } //criando tabela com as propriedades da classe Produto


    }
}
