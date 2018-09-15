using Microsoft.AspNet.Identity.EntityFramework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Web;

namespace VTS.AuthServer.Web.Infrastructure
{
    public class ApplicationUserStore : UserStore<ApplicationUser, ApplicationRole, Guid, ApplicationUserLogin, ApplicationUserRole, ApplicationUserClaim>
    {
        public ApplicationUserStore(ApplicationDbContext context)
            : base(context)
        {
        }

        public Task<bool> GetIsApprovedAsync(Guid userId)
        {
            var db = Context as ApplicationDbContext;
            if (db != null)
            {
                var user = db.Users.FirstOrDefault(u => u.Id == userId);

                if (user != null)
                    return Task.FromResult(user.IsApproved);
            }

            return Task.FromResult(false);
        }
    }
}