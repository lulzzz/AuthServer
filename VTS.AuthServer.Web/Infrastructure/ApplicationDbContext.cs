using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Linq;
using System.Security.Claims;
using System.Web;

namespace VTS.AuthServer.Web.Infrastructure
{
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser, ApplicationRole, Guid, ApplicationUserLogin, ApplicationUserRole, ApplicationUserClaim>
    {
        //public DbSet<Audience> Audiences { get; set; }
        //public DbSet<UserValidationLog> UserValidationLogs { get; set; }
        //public DbSet<UserValidationMethod> UserValidationMethods { get; set; }
        //public DbSet<NPSSurvey> NPSSurveys { get; set; }
        //public DbSet<RefreshToken> RefreshTokens { get; set; }

        public ApplicationDbContext()
            : base("VTSMembershipConnectionString")
        {
            //Configuration.ProxyCreationEnabled = false;
            //Configuration.LazyLoadingEnabled = false;
        }

        public static ApplicationDbContext Create()
        {
            return new ApplicationDbContext();
        }

        protected override void OnModelCreating(DbModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            modelBuilder.Properties<DateTimeOffset>().Configure(p => p.HasPrecision(3));
        }
    }
}