using OKTA_SSO_SignInSignUp.DBHelper;
using OKTA_SSO_SignInSignUp.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace OKTA_SSO_SignInSignUp.Controllers
{
    
    public class CourseController : Controller
    {
        DbHelper db = new DbHelper();

        [Authorize(Roles = "Admin,Manager")]
        public ActionResult Index()
        {
            // If you already have DbHelper.GetAllUsers(), call that instead
            List<Course> courses = db.GetAllCourses();
            return View(courses);
        }

        [Authorize(Roles = "Student")]
        public ActionResult MyCourse()
        {
            // If you already have DbHelper.GetAllUsers(), call that instead
            //List<Course> courses = db.GetAllCourses();
            return View();
        }
    }
}