using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using AzureADCoreAuthentication.Models;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;
using AzureADCoreAuthentication.Helpers;

namespace AzureADCoreAuthentication.Controllers
{
    [Authorize]
    public class HomeController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
        [Authorize(Policy = "Member")]
        public IActionResult About()
        {
            ViewData["Message"] = "Your application description page.";

            return View((ClaimsPrincipal)this.User);
        }

        [Authorize(Policy = "User")]
        public IActionResult Contact()
        {
            ViewData["Message"] = "Your contact page.";

            return View();
        }

        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
