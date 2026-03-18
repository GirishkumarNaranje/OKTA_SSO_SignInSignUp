using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Xml.Linq;

namespace OKTA_SSO_SignInSignUp.Models
{
    public class Course
    {
        public int Id { get; set; }

        public string Name { get; set; }

        public int? Totalmarks { get; set; }

        public bool? IsDeleted { get; set; }

        public DateTime? CreatedDate { get; set; }
    }
}