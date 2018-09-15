using Microsoft.AspNet.Identity.EntityFramework;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Web;

namespace VTS.AuthServer.Web.Infrastructure
{
    public class ApplicationRole : IdentityRole<Guid, ApplicationUserRole>
    {
        public Guid ApplicationId { get; set; }
        [Required]
        [MaxLength(256)]
        public string LoweredName { get; set; }
        public string Description { get; set; }

        public ApplicationRole() : this(string.Empty) { }
        public ApplicationRole(string name)
        {
            Id = Guid.NewGuid();

            Name = name;
            LoweredName = name.ToLower();
            ApplicationId = new Guid("CE311C6E-C5D2-4B75-A113-5D10BED0DA72");
        }
    }
}