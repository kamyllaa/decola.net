using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;
using Decolei.net.Interfaces; 
using Decolei.net.Repositories; 

namespace Decolei.net.Models
{
    public class Usuario : IdentityUser<int>
    {
        // Id, UserName, Email, PasswordHash, PhoneNumber já vêm do IdentityUser<int>

        // Propriedades EXCLUSIVAS do nosso banco/tabela
        public string? Documento { get; set; }

        [Required]
        [RegularExpression("^(CLIENTE|ATENDENTE|ADMIN)$", ErrorMessage = "Perfil inválido.")]
        public string? Perfil { get; set; } // coluna customizada de "Role"

        // NOVA PROPRIEDADE PARA O NOME COMPLETO DE EXIBIÇÃO
        public string? NomeCompleto { get; set; } // Esta é a propriedade que aceitará espaços

        public virtual ICollection<Reserva> Reservas { get; set; } = new List<Reserva>();
        public virtual ICollection<Avaliacao> Avaliacoes { get; set; } = new List<Avaliacao>();
    }
}