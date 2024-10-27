using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.V4.Pages.Account.Internal;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using mvc_app.DbContext;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using mvc_app.Models;
using Microsoft.VisualStudio.Web.CodeGenerators.Mvc.Templates.BlazorIdentity.Pages;

namespace mvc_app.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class APIAuthController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly IConfiguration _configuration;
        public APIAuthController(
            UserManager<IdentityUser> userManager,
            SignInManager<IdentityUser> signInManager,
            IConfiguration configuration
            )
        {
            _userManager = userManager;
            _configuration = configuration;
            _signInManager = signInManager;
        }
        //Register
        //https:localhost:[port]/api/register
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] Models.RegisterModel model)
        {
            var user = new IdentityUser {
                UserName = model.Email,
                Email = model.Email
            };
            var result = await _userManager.CreateAsync(user, model.Password);
            if (result.Succeeded)
            {
                return Ok(new { massage = "User registered Successfully" });
            }
            else
            {
                return BadRequest(result.Errors);
            }
        }
        //Register
        //https:localhost:[port]/api/login
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] Models.LoginModel model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                return Unauthorized("Invalid login attempt");
            }
            var result = await _signInManager.CheckPasswordSignInAsync(user, model.Password, false);
            if (result.Succeeded) 
            {
                var token = GenerateJwtToken(user);
                return Ok(new { Token = token });
            }
            return Unauthorized("Invalid login attempt");
        }

        private string GenerateJwtToken(IdentityUser user)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_configuration["Jwt:Key"]);
            var tokenDescriptior = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.NameIdentifier, user.Id),
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(ClaimTypes.Email, user.Email)
                }),
                Expires = DateTime.UtcNow.AddMinutes(Convert.ToDouble(_configuration["Jwt:DurationInMinutes"])),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.Aes128CbcHmacSha256)
            };
            var token = tokenHandler.CreateToken(tokenDescriptior);
            return tokenHandler.WriteToken(token);
        }
    }
}
