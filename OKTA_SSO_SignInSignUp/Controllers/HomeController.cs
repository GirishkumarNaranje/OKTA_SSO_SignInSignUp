using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Web.Security;

namespace OKTA_SSO_SignInSignUp.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            return View();
        }

        [Authorize]
        public ActionResult About()
        {
            ViewBag.Message = "Your application description page.";

            return View();
        }

        [Authorize]
        public ActionResult Contact()
        {
            ViewBag.Message = "Your contact page.";

            return View();
        }

        [Authorize]
        public ActionResult WhoAmI()
        {
            var name = User.Identity.Name ?? "(null)";
            var auth = Request.IsAuthenticated;
            bool isAdmin = User.IsInRole("Admin");
            bool isManager = User.IsInRole("Manager");
            bool isStudent = User.IsInRole("Student");

            return Content(
                $"Auth={auth}, Name={name}, Admin={isAdmin}, Manager={isManager}, Student={isStudent}"
            );
        }

        [AllowAnonymous]
        public ActionResult TicketInfo()
        {
            var c = Request.Cookies[FormsAuthentication.FormsCookieName];
            if (c == null) return Content(".ASPXAUTH cookie not found");

            try
            {
                var t = FormsAuthentication.Decrypt(c.Value);
                if (t == null) return Content("Ticket decrypt failed");
                return Content(
                    $"Name={t.Name}, IsPersistent={t.IsPersistent}, Expires={t.Expiration}, UserData='{t.UserData}'"
                );
            }
            catch (Exception ex)
            {
                return Content("Decrypt error: " + ex.Message);
            }
        }
    }
}