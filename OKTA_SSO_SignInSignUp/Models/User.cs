using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace OKTA_SSO_SignInSignUp.Models
{
    public class User
    {
        public int Id { get; set; }

        public string FirstName { get; set; }

        public string LastName { get; set; }

        public string Username { get; set; }

        public string Email { get; set; }

        public string Password { get; set; }

        public DateTime? CreatedDate { get; set; }

        public string Role { get; set; }
    }
}