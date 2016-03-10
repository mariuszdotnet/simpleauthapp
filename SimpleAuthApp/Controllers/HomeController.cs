using SimpleAuthApp.Filters;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace SimpleAuthApp.Controllers
{
    
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            return View();
        }


        [AuthorizeAD(Groups = "ALLBBBCA")]
        public ActionResult About()
        {
            ViewBag.Message = "Your application description page.";
            ViewBag.UserGroup = Constants.UserGroup;
            return View();
        }

        [AuthorizeAD(Groups = "ADMIN")]
        public ActionResult Contact()
        {
            ViewBag.Message = "Your contact page.";

            return View();
        }
    }
}