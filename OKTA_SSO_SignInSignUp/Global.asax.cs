using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Web.Optimization;
using System.Web.Routing;
using System.Security.Principal;
using System.Web.Security;

namespace OKTA_SSO_SignInSignUp
{
    public class MvcApplication : System.Web.HttpApplication
    {
        protected void Application_Start()
        {
            AreaRegistration.RegisterAllAreas();
            FilterConfig.RegisterGlobalFilters(GlobalFilters.Filters);
            RouteConfig.RegisterRoutes(RouteTable.Routes);
            BundleConfig.RegisterBundles(BundleTable.Bundles);
        }

        protected void Application_AuthenticateRequest(object sender, EventArgs e)
        {
            HttpCookie authCookie = Request.Cookies[FormsAuthentication.FormsCookieName];
            if (authCookie != null)
            {
                try
                {
                    FormsAuthenticationTicket ticket = FormsAuthentication.Decrypt(authCookie.Value);
                    if (ticket != null && !ticket.Expired)
                    {
                        string[] roles = ticket.UserData.Split(',');
                        var identity = new System.Security.Principal.GenericIdentity(ticket.Name, "Forms");
                        var principal = new System.Security.Principal.GenericPrincipal(identity, roles);
                        HttpContext.Current.User = principal;
                    }
                }
                catch { }
            }
        }

        // IMPORTANT: Add this to suppress Forms Auth redirect for OWIN
        protected void Application_EndRequest(object sender, EventArgs e)
        {
            var context = new HttpContextWrapper(HttpContext.Current);

            // If it's a 401 and we're on an Okta path, don't let Forms Auth redirect
            if (HttpContext.Current.Response.StatusCode == 401)
            {
                var path = HttpContext.Current.Request.Path;
                if (path.Contains("/Account/OktaLogin") ||
                    path.Contains("/authorization-code/callback"))
                {
                    HttpContext.Current.Response.SuppressFormsAuthenticationRedirect = true;
                }
            }
        }
    }
}
