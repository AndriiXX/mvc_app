using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using mvc_app.Models;
using mvc_app.Services;

namespace mvc_app.Controllers
{
    public class ProductsController : Controller
    {
        private readonly IServiceProducts _serviceProducts;
        public ProductsController(IServiceProducts serviceProducts)
        {
            _serviceProducts = serviceProducts;
        }
        //GET: http://localhost:[port]/products
        public async Task<ViewResult> Index()
        {
            var products = await _serviceProducts.ReadAsync();
            return View(products);
        }
        //GET: http://localhost:[port]/products/details/{id}
        public async Task<ViewResult> Details(int id)
        {
            var product = await _serviceProducts.GetByIdAsync(id);
            return View(product);
        }
        
        [Authorize(Roles = "admin")]
        [HttpGet]
        //GET: http://localhost:[port]/products/create
        public ViewResult Create() => View();
        [Authorize(Roles = "admin")]
        //POST: http://localhost:[port]/products/create
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([Bind("Id,Name,Price,Description")] Product product)
        {
            if (ModelState.IsValid)
            {
                await _serviceProducts.CreateAsync(product);
                return RedirectToAction(nameof(Index));
            }
            return View(product);
        }
        [Authorize(Roles = "admin")]
        [HttpGet]
        public ViewResult Update() => View();
        [Authorize(Roles = "admin")]
        //POST: http://localhost:[port]/products/update/{id}
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Update(int id, [Bind("Id,Name,Price,Description")] Product product)
        {
            if (ModelState.IsValid)
            {
                await _serviceProducts.UpdateAsync(id, product);
                return RedirectToAction(nameof(Index));
            }
            return View(product);
        }
        [Authorize(Roles = "admin")]
        [HttpGet]
        public ViewResult Delete() => View();
        [Authorize(Roles = "admin")]
        //POST: http://localhost:[port]/products/delete/{id}
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Delete(int id)
        {
            await _serviceProducts.DeleteAsync(id);
            return RedirectToAction(nameof(Index));
        }
    }
}
