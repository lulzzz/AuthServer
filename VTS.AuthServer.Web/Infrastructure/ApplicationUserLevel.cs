using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace VTS.AuthServer.Web.Infrastructure
{
    public enum ApplicationUserLevel : byte
    {
        None = 0,           // None specified
        Legacy = 1,         // Legacy SQL Membership provider users that were migrated to the new AspNet Identity 2 provider
        Upgraded = 2,       // All new user accounts after migration to the new AspNet Identity2 provider
        FirstAccount = 3    // First account will be created when Sertifi comes signed and new Customer, along with mobile group and vehicles is created
    }
}