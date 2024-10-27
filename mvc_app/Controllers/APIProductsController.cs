using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using mvc_app.Models;
using mvc_app.Services;
using System.Security.Claims;

namespace mvc_app.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class APIProductsController : ControllerBase
    {
        private readonly IServiceProducts _serviceProducts;

        public APIProductsController(IServiceProducts? serviceProducts)
        {
            _serviceProducts = serviceProducts;
        }

        // Получение всех постов (доступно всем)
        [HttpGet]
        public async Task<IActionResult> GetAllProducts()
        {
            var products = await _serviceProducts.ReadAsync();
            return Ok(products);
        }

        // Получение поста по Id (доступно всем)
        [HttpGet("{id}")]
        public async Task<IActionResult> GetProductById(int id)
        {
            var product = await _serviceProducts.GetByIdAsync(id);
            if (product == null) return NotFound();
            return Ok(product);
        }

        // Создание нового поста (доступно только авторизованным пользователям)
        [Authorize(Roles = "admin")]
        [HttpPost]
        public async Task<IActionResult> CreateProduct([FromBody] Product product)
        {
            var product_created = _serviceProducts.CreateAsync(product);

            return Ok(product_created);
        }

        [Authorize(Roles = "admin")]
        [HttpPut("{id}")]
        public async Task<IActionResult> UpdateProduct(int id,[FromBody] Product product)
        {
            var product_updated = await _serviceProducts.UpdateAsync(id, product);

            return Ok(product_updated);
        }

        // Удаление поста (доступно только авторизованным пользователям)
        [Authorize(Roles = "admin")]
        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteProduct(int id)
        {
            var deleted = await _serviceProducts.DeleteAsync(id);

            return Ok(new { message = deleted });
        }
    }
}
