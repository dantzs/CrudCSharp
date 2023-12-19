using System.ComponentModel.DataAnnotations;

namespace CrudCSharp.Model
{
    public class Produto
    {
        [Key]
        public int Id { get; set; }

        [Required(ErrorMessage ="O campo não {0} é obrigatorio")]
        public string? Nome { get; set; }

        [Required(ErrorMessage = "O campo não {0} é obrigatorio")]
        [Range(1,int.MaxValue, ErrorMessage = "O preço deve ser maior que 0")]
        public decimal Preco { get; set; }


        [Required(ErrorMessage = "O campo não {0} é obrigatorio")]
        public int QuantidadeEstoque { get; set; }

        [Required(ErrorMessage = "O campo não {0} é obrigatorio")]
        public string? Descricao { get; set; }

    }
}
