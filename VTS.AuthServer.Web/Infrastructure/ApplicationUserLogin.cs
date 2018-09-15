using Microsoft.AspNet.Identity.EntityFramework;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Web;

namespace VTS.AuthServer.Web.Infrastructure
{
    public class ApplicationUserLogin : IdentityUserLogin<Guid> { }
}