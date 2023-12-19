using CrudCSharp.Data;
using CrudCSharp.Model;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace CrudCSharp.Controllers
{
    [ApiController]
    [Route("/api/produtos")]
    public class ProdutoController : ControllerBase
    {
        private readonly ApiDbContext _context;

        public ProdutoController(ApiDbContext context) 
        {
            _context = context;
        }

        [HttpGet]
        public async Task<ActionResult<IEnumerable<Produto>>> GetProdutos() 
        {
            return await _context.Produtos.ToListAsync();
        }

        [HttpGet("{id:int}")]
        public async Task<ActionResult<Produto>> GetProduto(int id)
        {
            var produto = await _context.Produtos.FindAsync(id);

            return Ok(produto);
        }

        [HttpPost]
        public async Task<ActionResult<Produto>> PostProduto(Produto produto)
        {
            _context.Produtos.Add(produto);
            await _context.SaveChangesAsync();

            return CreatedAtAction(nameof(GetProduto), new {id = produto.Id}, produto);
        }

        [HttpPut("{id:int}")]
        public async Task<ActionResult<Produto>> PutProduto(int id, Produto produto)
        {
            _context.Produtos.Update(produto);
            await _context.SaveChangesAsync();
            return NoContent();
        }

        [HttpDelete("{id:int}")]
        public async Task<IActionResult> DeleteProduto(int id)
        {
            var produto = await _context.Produtos.FindAsync(id);

            _context.Produtos.Remove(produto);
            _context.SaveChangesAsync();

            return NoContent();
        }

    }
}
