using System.Web;
using System.Web.Mvc;

namespace OKTA_SSO_SignInSignUp
{
    public class FilterConfig
    {
        public static void RegisterGlobalFilters(GlobalFilterCollection filters)
        {
            filters.Add(new HandleErrorAttribute());
        }
    }
}
