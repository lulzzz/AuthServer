using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;

namespace VTS.AuthServer.Web.Infrastructure
{
    public class ApplicationUser : IdentityUser<Guid, ApplicationUserLogin, ApplicationUserRole, ApplicationUserClaim>
    {
        [MaxLength(100)]
        public string FirstName { get; set; }

        [MaxLength(100)]
        public string LastName { get; set; }

        [Required]
        public byte Level { get; set; }

        [Required]
        public DateTime CreateDate { get; set; }

        [Required]
        public Guid ApplicationId { get; set; }

        public string LoweredUserName { get; set; }

        public string MobileAlias { get; set; }

        public DateTime? LastActivityDate { get; set; }

        public string MobilePIN { get; set; }

        public string LoweredEmail { get; set; }

        [Required]
        public bool IsApproved { get; set; }

        [Required]
        public DateTime LastLoginDate { get; set; }

        public DateTime? LastPasswordChangedDate { get; set; }

        public DateTime? LastLockoutDate { get; set; }

        public string Comment { get; set; }

        public override int AccessFailedCount { get; set; }

        public string Title { get; set; }
        public bool RequiredFieldsSupplied { get; set; }

        public ApplicationUser() { }
        public ApplicationUser(string email) : this(Guid.NewGuid().ToString("N"), email) { }
        public ApplicationUser(string username, string email)
        {
            Id = Guid.NewGuid();
            Level = (byte)ApplicationUserLevel.Upgraded;
            CreateDate = DateTime.UtcNow;
            LastLoginDate = new DateTime(1753, 1, 1);
            LastActivityDate = new DateTime(1753, 1, 1);
            LastPasswordChangedDate = new DateTime(1753, 1, 1);
            ApplicationId = new Guid("CE311C6E-C5D2-4B75-A113-5D10BED0DA72");

            UserName = username;
            LoweredUserName = username.ToLower();

            Email = email;
            LoweredEmail = email.ToLower();

            IsApproved = true;
            TwoFactorEnabled = true;
            LockoutEnabled = true;
        }
    }
}