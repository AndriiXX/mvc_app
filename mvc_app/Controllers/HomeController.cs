using Microsoft.AspNetCore.Mvc;

namespace mvc_app.Controllers
{
    public class HomeController : Controller
    {
        public ViewResult Index()
        {
            return View();
        }
    }
}
