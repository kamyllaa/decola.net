using Decolei.net.DTOs;
using Decolei.net.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration; // Importar para acessar configurações

// Usings para JWT
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace Decolei.net.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UsuarioController : ControllerBase
    {
        private readonly UserManager<Usuario> _userManager;
        private readonly SignInManager<Usuario> _signInManager;
        private readonly RoleManager<IdentityRole<int>> _roleManager;
        private readonly IConfiguration _configuration; // Adicionado para acessar JwtSettings

        public UsuarioController(
            UserManager<Usuario> userManager,
            SignInManager<Usuario> signInManager,
            RoleManager<IdentityRole<int>> roleManager,
            IConfiguration configuration) // Injetar IConfiguration NO CONSTRUTOR
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;
            _configuration = configuration; // Atribuir
        }

        // --- ENDPOINT DE REGISTRO (COM LÓGICA DE PAPÉIS) ---
        [HttpPost("registrar")]
        public async Task<IActionResult> Registrar([FromBody] RegistroUsuarioDto registroDto)
        {
            if (!ModelState.IsValid) return BadRequest(ModelState);

            var usuarioExistente = await _userManager.FindByEmailAsync(registroDto.Email!);
            if (usuarioExistente != null)
            {
                return BadRequest("Este e-mail já está em uso.");
            }

            var novoUsuario = new Usuario
            {
                UserName = registroDto.Email, // UserName do Identity será o email
                Email = registroDto.Email,
                Documento = registroDto.Documento,
                PhoneNumber = registroDto.Telefone,
                Perfil = "CLIENTE",
                NomeCompleto = registroDto.Nome // Nome completo com espaços
            };

            var resultado = await _userManager.CreateAsync(novoUsuario, registroDto.Senha!);

            if (resultado.Succeeded)
            {
                // Garante que o papel "CLIENTE" existe no banco. Se não, ele o cria.
                if (!await _roleManager.RoleExistsAsync("CLIENTE"))
                {
                    await _roleManager.CreateAsync(new IdentityRole<int>("CLIENTE"));
                }
                // Adiciona o novo usuário ao papel "CLIENTE".
                await _userManager.AddToRoleAsync(novoUsuario, "CLIENTE");

                // Para APIs com JWT, não fazemos SignInAsync no registro
                // await _signInManager.SignInAsync(novoUsuario, isPersistent: false);
                return Ok(new { Message = "Usuário cliente registrado com sucesso!" });
            }

            foreach (var erro in resultado.Errors)
            {
                ModelState.AddModelError(string.Empty, erro.Description);
            }
            return BadRequest(ModelState);
        }

        // --- ENDPOINT DE LOGIN (LÓGICA CORRIGIDA E GERANDO JWT) ---
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginUsuarioDto loginDto)
        {
            if (!ModelState.IsValid) return BadRequest(ModelState);

            // 1. BUSCAR O USUÁRIO PELO E-MAIL
            var usuario = await _userManager.FindByEmailAsync(loginDto.Email!);

            if (usuario == null)
            {
                return Unauthorized("Email ou senha inválidos.");
            }

            // 2. VERIFICAR A SENHA
            var resultado = await _signInManager.CheckPasswordSignInAsync(usuario, loginDto.Senha!, lockoutOnFailure: true);

            if (resultado.Succeeded)
            {
                // --- GERAÇÃO DO JWT ---
                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.NameIdentifier, usuario.Id.ToString()),
                    new Claim(ClaimTypes.Name, usuario.UserName!), // Usando UserName (que é o email)
                    new Claim(ClaimTypes.Email, usuario.Email!),
                    new Claim("NomeCompleto", usuario.NomeCompleto!) // Adicione o nome completo como uma claim customizada
                };

                // Adicionar as roles do usuário como claims
                var userRoles = await _userManager.GetRolesAsync(usuario);
                foreach (var role in userRoles)
                {
                    claims.Add(new Claim(ClaimTypes.Role, role));
                }

                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JwtSettings:Key"]!));
                var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
                var expires = DateTime.Now.AddDays(7); // Token válido por 7 dias (ajuste conforme necessidade)

                var token = new JwtSecurityToken(
                    issuer: _configuration["JwtSettings:Issuer"],
                    audience: _configuration["JwtSettings:Audience"],
                    claims: claims,
                    expires: expires,
                    signingCredentials: creds
                );

                var tokenString = new JwtSecurityTokenHandler().WriteToken(token);

                return Ok(new { Token = tokenString, Message = "Login bem-sucedido!" });
            }

            if (resultado.IsLockedOut)
            {
                return Unauthorized("Esta conta está bloqueada. Tente novamente mais tarde.");
            }

            return Unauthorized("Email ou senha inválidos.");
        }

        // --- NOVO ENDPOINT PARA REGISTRAR ADMINISTRADORES ---
        // Apenas usuários com a role "ADMIN" podem acessar este endpoint
        [Authorize(Roles = "ADMIN")] // <--- AGORA ESTÁ EM MAIÚSCULAS PARA CONDIZER COM A ROLE
        [HttpPost("registrar-admin")]
        public async Task<IActionResult> RegistrarAdmin([FromBody] RegistroUsuarioDto registroDto)
        {
            if (!ModelState.IsValid) return BadRequest(ModelState);

            var usuarioExistente = await _userManager.FindByEmailAsync(registroDto.Email!);
            if (usuarioExistente != null)
            {
                return BadRequest("Este e-mail já está em uso.");
            }

            var novoUsuario = new Usuario
            {
                UserName = registroDto.Email, // UserName do Identity será o email
                Email = registroDto.Email,
                Documento = registroDto.Documento,
                PhoneNumber = registroDto.Telefone,
                Perfil = "ADMIN", // Definindo o perfil como ADMIN
                NomeCompleto = registroDto.Nome // Nome completo com espaços
            };

            var resultado = await _userManager.CreateAsync(novoUsuario, registroDto.Senha!);

            if (resultado.Succeeded)
            {
                // Garante que o papel "ADMIN" existe. Se não, ele o cria.
                if (!await _roleManager.RoleExistsAsync("ADMIN"))
                {
                    await _roleManager.CreateAsync(new IdentityRole<int>("ADMIN"));
                }
                // Adiciona o novo usuário ao papel "ADMIN".
                await _userManager.AddToRoleAsync(novoUsuario, "ADMIN");

                return Ok(new { Message = "Usuário administrador registrado com sucesso!" });
            }

            foreach (var erro in resultado.Errors)
            {
                ModelState.AddModelError(string.Empty, erro.Description);
            }
            return BadRequest(ModelState);
        }
        // --- NOVO: LISTAR USUÁRIOS (apenas para ADMIN) ---
        [Authorize(Roles = "ADMIN")]
        [HttpGet]
        public IActionResult ListarUsuarios()
        {
            var usuarios = _userManager.Users.ToList();

            var resultado = usuarios.Select(u => new
            {
                u.Id,
                u.NomeCompleto,
                u.Email,
                u.Perfil
            });

            return Ok(resultado);
        }
    }
}