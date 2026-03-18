using OKTA_SSO_SignInSignUp.Models;   // adjust to your namespace
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using OKTA_SSO_SignInSignUp.DBHelper;


namespace OKTA_SSO_SignInSignUp.Controllers
{
    [Authorize(Roles = "Admin")] // only Admin can view all users (change as you like)
    public class UserController : Controller
    {
        DbHelper db = new DbHelper();

        // GET: /User
        public ActionResult Index()
        {
            // If you already have DbHelper.GetAllUsers(), call that instead
            List<User> users = db.GetAllUsers();
            return View(users);
        }

        // GET: /User/Edit/6
        public ActionResult Edit(int id)
        {
            var user = db.GetUserById(id);
            if (user == null) return HttpNotFound();
            return View(user);
        }

        // POST: /User/Edit/6
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Edit(User user)
        {
            if (!ModelState.IsValid)
                return View(user);

            // Optional guard: don't allow username to be blank
            if (string.IsNullOrWhiteSpace(user.Username))
            {
                ModelState.AddModelError("Username", "Username is required.");
                return View(user);
            }

            // Optional: prevent role becoming NULL
            if (string.IsNullOrWhiteSpace(user.Role))
            {
                ModelState.AddModelError("Role", "Role is required.");
                return View(user);
            }

            db.EditUser(user);
            TempData["SuccessMessage"] = "User updated successfully.";
            return RedirectToAction("Index");
        }


        // GET: /User/Delete/6  (confirmation page)
        public ActionResult Delete(int id)
        {
            var user = db.GetUserById(id);
            if (user == null) return HttpNotFound();
            return View(user);
        }

        // POST: /User/Delete/6
        [HttpPost]
        [ValidateAntiForgeryToken]
        [ActionName("Delete")]
        public ActionResult DeleteConfirmed(int id)
        {
            // Optional guard: don't allow an admin to delete current self
            var currentUserName = User.Identity.Name;
            var user = db.GetUserById(id);
            if (user == null) return HttpNotFound();

            if (string.Equals(user.Username, currentUserName, StringComparison.OrdinalIgnoreCase))
            {
                TempData["ErrorMessage"] = "You cannot delete your own account while logged in.";
                return RedirectToAction("Index");
            }

            db.DeleteUser(id);
            TempData["SuccessMessage"] = "User deleted successfully.";
            return RedirectToAction("Index");
        }

    }
}