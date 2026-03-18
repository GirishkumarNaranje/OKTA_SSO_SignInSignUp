using OKTA_SSO_SignInSignUp.DBHelper;
using OKTA_SSO_SignInSignUp.Models;
using Microsoft.Owin.Security.Cookies;
using Okta.AspNet;
using System;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Web.Security;

namespace OKTA_SSO_SignInSignUp.Controllers
{
    public class AccountController : Controller
    {
        DbHelper db = new DbHelper();

        // GET: Account
        public ActionResult Index()
        {
            return View();
        }

        #region OKTA SSO AUTHENTICATION

        /// <summary>
        /// Initiates Okta SSO login
        /// </summary>
        [AllowAnonymous]
        public ActionResult OktaLogin(string returnUrl)
        {
            if (!HttpContext.User.Identity.IsAuthenticated)
            {
                // Store return URL for after authentication
                if (!string.IsNullOrEmpty(returnUrl))
                {
                    Session["ReturnUrl"] = returnUrl;
                }

                // Challenge Okta authentication
                var properties = new Microsoft.Owin.Security.AuthenticationProperties
                {
                    RedirectUri = Url.Action("OktaCallback", "Account", null, Request.Url.Scheme)
                };

                HttpContext.GetOwinContext().Authentication.Challenge(
                    properties,
                    OktaDefaults.MvcAuthenticationType);

                // CRITICAL: End response immediately to prevent Forms Auth redirect
                HttpContext.Response.SuppressFormsAuthenticationRedirect = true;
                HttpContext.Response.End();

                return new EmptyResult();
            }

            // User is already authenticated via Okta
            string oktaEmail = User.Identity.Name;
            SyncOktaUserToDatabase(oktaEmail);

            // Redirect to return URL or home
            if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
                return Redirect(returnUrl);

            return RedirectToAction("Index", "Home");
        }

        /// <summary>
        /// Handles Okta callback after successful authentication
        /// </summary>
        [AllowAnonymous]
        public ActionResult OktaCallback()
        {
            if (HttpContext.User.Identity.IsAuthenticated)
            {
                // User successfully authenticated via Okta
                string oktaEmail = User.Identity.Name;
                SyncOktaUserToDatabase(oktaEmail);

                // Get return URL from session
                string returnUrl = Session["ReturnUrl"] as string;
                Session.Remove("ReturnUrl");

                if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
                    return Redirect(returnUrl);

                return RedirectToAction("Index", "Home");
            }

            // Authentication failed, redirect to login
            return RedirectToAction("Login");
        }

        /// <summary>
        /// Okta logout
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult OktaLogout()
        {
            if (HttpContext.User.Identity.IsAuthenticated)
            {
                HttpContext.GetOwinContext().Authentication.SignOut(
                    CookieAuthenticationDefaults.AuthenticationType,
                    OktaDefaults.MvcAuthenticationType);
            }

            ClearSessionAndCookies();
            return RedirectToAction("Login", "Account");
        }

        /// <summary>
        /// User profile page (shows Okta claims)
        /// </summary>
        [Authorize]
        public ActionResult Profile()
        {
            return View();
        }

        #endregion

        #region FORMS AUTHENTICATION (EXISTING)

        /// <summary>
        /// User registration
        /// </summary>
        [AllowAnonymous]
        public ActionResult Register()
        {
            return View();
        }

        [HttpPost, AllowAnonymous, ValidateAntiForgeryToken]
        public ActionResult Register(User user)
        {
            if (ModelState.IsValid)
            {
                try
                {
                    db.RegisterUser(user);
                    TempData["SuccessMessage"] = "Registration successful! Please login.";
                    return RedirectToAction("Login");
                }
                catch (Exception ex)
                {
                    ViewBag.Message = "Registration failed: " + ex.Message;
                }
            }
            return View(user);
        }

        /// <summary>
        /// Login page (shows both Okta and Forms Auth options)
        /// </summary>
        [AllowAnonymous]
        public ActionResult Login(string returnUrl)
        {
            // If already authenticated, redirect appropriately
            if (Request.IsAuthenticated)
            {
                if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
                    return Redirect(returnUrl);
                return RedirectToAction("Index", "Home");
            }

            ViewBag.ReturnUrl = returnUrl;
            return View();
        }

        /// <summary>
        /// Forms Authentication login
        /// </summary>
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult Login(string username, string password, bool? rememberMe, string returnUrl)
        {
            var user = db.Login(username, password);

            if (user != null)
            {
                // Set session variables
                Session["User"] = user.Username;
                Session["FirstName"] = user.FirstName;
                Session["LastName"] = user.LastName;
                Session["LoginMethod"] = "FormsAuth";

                // Create Forms Authentication ticket with roles
                string rolesCsv = (user.Role ?? "").Trim();

                var ticket = new FormsAuthenticationTicket(
                    1,
                    user.Username,
                    DateTime.Now,
                    DateTime.Now.AddMinutes(rememberMe == true ? 43200 : 60),
                    rememberMe ?? false,
                    rolesCsv
                );

                string enc = FormsAuthentication.Encrypt(ticket);
                var cookie = new HttpCookie(FormsAuthentication.FormsCookieName, enc)
                {
                    HttpOnly = true,
                    Secure = Request.IsSecureConnection
                };
                if (ticket.IsPersistent) cookie.Expires = ticket.Expiration;

                Response.Cookies.Add(cookie);

                // Redirect
                if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
                    return Redirect(returnUrl);

                return RedirectToAction("Index", "Home");
            }

            ViewBag.Message = "Invalid username or password.";
            ViewBag.ReturnUrl = returnUrl;
            return View();
        }

        #endregion

        #region UNIFIED LOGOUT

        /// <summary>
        /// Unified logout (handles both Okta and Forms Auth)
        /// </summary>
        [Authorize]
        public ActionResult Logout()
        {
            // Check if logged in via Okta
            var loginMethod = Session["LoginMethod"]?.ToString();

            if (loginMethod == "Okta")
            {
                // Okta logout
                if (HttpContext.User.Identity.IsAuthenticated)
                {
                    HttpContext.GetOwinContext().Authentication.SignOut(
                        CookieAuthenticationDefaults.AuthenticationType,
                        OktaDefaults.MvcAuthenticationType);
                }
            }

            // Clear Forms Authentication and session
            ClearSessionAndCookies();

            return RedirectToAction("Login", "Account");
        }

        #endregion

        #region DASHBOARD

        public ActionResult Dashboard()
        {
            if (Session["User"] == null && !Request.IsAuthenticated)
                return RedirectToAction("Login", "Account");

            return View();
        }

        #endregion

        #region HELPER METHODS

        /// <summary>
        /// Sync Okta user to local database
        /// </summary>
        private void SyncOktaUserToDatabase(string email)
        {
            try
            {
                // Check if user exists
                var existingUser = db.GetUserByEmail(email);

                if (existingUser == null)
                {
                    // Get claims from Okta
                    var claims = ((System.Security.Claims.ClaimsIdentity)User.Identity).Claims;

                    var newUser = new User
                    {
                        Username = email,
                        Email = email,
                        FirstName = claims.FirstOrDefault(c => c.Type == "given_name")?.Value ?? "",
                        LastName = claims.FirstOrDefault(c => c.Type == "family_name")?.Value ?? "",
                        Role = "Student" // Default role for Okta users
                    };

                    // Save to database
                    db.RegisterOktaUser(newUser);

                    // Update session
                    Session["User"] = newUser.Username;
                    Session["FirstName"] = newUser.FirstName;
                    Session["LastName"] = newUser.LastName;
                    Session["LoginMethod"] = "Okta";
                }
                else
                {
                    // User exists, update session
                    Session["User"] = existingUser.Username;
                    Session["FirstName"] = existingUser.FirstName;
                    Session["LastName"] = existingUser.LastName;
                    Session["LoginMethod"] = "Okta";
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error syncing Okta user: {ex.Message}");
            }
        }

        /// <summary>
        /// Clear session and authentication cookies
        /// </summary>
        private void ClearSessionAndCookies()
        {
            FormsAuthentication.SignOut();
            Session.Clear();
            Session.Abandon();

            var cookie = new HttpCookie(FormsAuthentication.FormsCookieName, "")
            {
                Expires = DateTime.Now.AddYears(-1)
            };
            Response.Cookies.Add(cookie);

            // Prevent back-button cached pages
            Response.Cache.SetCacheability(HttpCacheability.NoCache);
            Response.Cache.SetNoStore();
            Response.Cache.SetExpires(DateTime.UtcNow.AddMinutes(-1));
        }

        #endregion
    }
}