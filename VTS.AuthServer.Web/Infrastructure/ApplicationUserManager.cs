using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Web;

namespace VTS.AuthServer.Web.Infrastructure
{
    public class ApplicationUserManager : UserManager<ApplicationUser, Guid>
    {
        private IAuthenticationManager authManager;
        private string requestBaseUrl;
        private readonly Dictionary<ApplicationUserLevel, string> _welcomeEmailTemplates = new Dictionary<ApplicationUserLevel, string>
        {
            { ApplicationUserLevel.Legacy, "VTS.Membership.AuthServer.Content.UpgradeAccountEmail.htm" },
            { ApplicationUserLevel.Upgraded, "VTS.Membership.AuthServer.Content.WelcomeEmail.htm" },
            { ApplicationUserLevel.FirstAccount, "VTS.Membership.AuthServer.Content.CustomerEnrollmentEmail.htm" },
        };

        public ApplicationUserManager(IUserStore<ApplicationUser, Guid> store)
            : base(store)
        {
            //this.PasswordHasher = new SqlPasswordHasher();
        }

        public static ApplicationUserManager Create(IdentityFactoryOptions<ApplicationUserManager> options, IOwinContext context)
        {
            var appDbContext = context.Get<ApplicationDbContext>();
            var appUserManager = new ApplicationUserManager(new ApplicationUserStore(appDbContext))
            {
                requestBaseUrl = context.Request.Uri.GetLeftPart(UriPartial.Authority),
                authManager = context.Authentication
            };

            appUserManager.EmailService = new Services.EmailService();

            var dataProtectionProvider = options.DataProtectionProvider;
            if (dataProtectionProvider != null)
            {
                appUserManager.UserTokenProvider = new DataProtectorTokenProvider<ApplicationUser, Guid>(dataProtectionProvider.Create("ASP.NET Identity"))
                {
                    //Code for email confirmation and reset password life time
                    TokenLifespan = TimeSpan.FromDays(30)
                };
            }

            //Configure validation logic for usernames
            appUserManager.UserValidator = new UserValidator<ApplicationUser, Guid>(appUserManager)
            {
                AllowOnlyAlphanumericUserNames = false,
                RequireUniqueEmail = true
            };

            //Configure validation logic for passwords
            appUserManager.PasswordValidator = new PasswordValidator
            {
                RequiredLength = 6,
                RequireNonLetterOrDigit = false,
                RequireDigit = false,
                RequireLowercase = false,
                RequireUppercase = false,
            };

            return appUserManager;
        }
        /*
        public static ApplicationUserManager Current
        {
            get
            {
                if (HttpContext.Current != null)
                {
                    try
                    {
                        return HttpContext.Current.GetOwinContext().GetUserManager<ApplicationUserManager>();
                    }
                    catch { }
                }

                return null;
            }
        }

        public UserValidationResult ValidateUser(string username, string password)
        {
            return VTS.Utility.AsyncHelpers.RunSync<UserValidationResult>(() => ValidateUserAsync(username, password));
        }
        public async Task<UserValidationResult> ValidateUserAsync(string username, string password)
        {
            ApplicationUser user = await FindByNameAsync(username);
            Entities.UserValidationMethodEnum method = Entities.UserValidationMethodEnum.Username;

            if (user == null && username.IsValidEmail())
            {
                user = await FindByEmailAsync(username);
                method = Entities.UserValidationMethodEnum.Email;
            }

            var result = await ValidateUserAsync(user, password);
            result.Method = method;

            if (result.Succeeded && UserValidationLogManager.Current != null)
                UserValidationLogManager.Current.AddNewEntry(user.Id, result.Method);

            return result;
        }
        public async Task<UserValidationResult> ValidateUserAsync(Guid userId, string password)
        {
            var user = await this.FindByIdAsync(userId);

            var result = await ValidateUserAsync(user, password);

            if (result.Succeeded)
            {
                result.Method = Entities.UserValidationMethodEnum.UserId;
                UserValidationLogManager.Current.AddNewEntry(user.Id, result.Method);
            }

            return result;
        }
        public async Task<UserValidationResult> ValidateUserAsync(ApplicationUser user, string password)
        {
            // Invalid user, fail login
            if (user == null || await IsLockedOutAsync(user.Id) || !user.IsApproved)
            {
                return new UserValidationResult(user == null ? UserValidationResult.AccountNotFound : UserValidationResult.AccountSuspended);
            }

            if (!user.EmailConfirmed)
            {
                return new UserValidationResult(user, UserValidationResult.EmailNotConfirmed);
            }

            // Valid user, verify password
            var result = PasswordHasher.VerifyHashedPassword(user.PasswordHash, password);
            if (result == PasswordVerificationResult.SuccessRehashNeeded)
            {
                // Logged in using old Membership credentials - update hashed password in database
                // Since we update the user on login anyway, we'll just set the new hash
                // Optionally could set password via the ApplicationUserManager by using
                // RemovePassword() and AddPassword()
                user.PasswordHash = PasswordHasher.HashPassword(password);
            }
            else if (result != PasswordVerificationResult.Success)
            {
                bool lockedOut = false;

                // Failed login, increment failed login counter
                // Lockout for 24 hours if more than 10 failed attempts
                user.AccessFailedCount++;
                if (user.AccessFailedCount >= 10)
                {
                    user.LastLockoutDate = DateTime.UtcNow;
                    user.LockoutEndDateUtc = DateTime.UtcNow.AddHours(24);
                    lockedOut = true;
                }
                await UpdateAsync(user);

                if (lockedOut)
                {
                    await SendLockoutEmailAsync(user.Id, user.LastLockoutDate.Value);
                    return new UserValidationResult(UserValidationResult.ExceededMaxTryCount);
                }

                return new UserValidationResult(UserValidationResult.FailedAttempt);
            }

            return UserValidationResult.Success(user);
        }
        public async Task UserAuthenticatedAsync(Guid userId, bool rememberMe)
        {
            var user = this.FindById(userId);

            if (user != null)
                await UserAuthenticatedAsync(user, rememberMe);
        }
        public async Task UserAuthenticatedAsync(ApplicationUser user, bool rememberMe)
        {
            try
            {
                var userIdentity = await user.GenerateUserIdentityAsync(this, DefaultAuthenticationTypes.ApplicationCookie, rememberMe);

                authManager.SignOut(DefaultAuthenticationTypes.ApplicationCookie);
                authManager.SignIn(new AuthenticationProperties
                {
                    IsPersistent = rememberMe,
                    AllowRefresh = true,
                    ExpiresUtc = DateTime.UtcNow.AddDays(1)
                }, userIdentity);

                user.AccessFailedCount = 0;
                user.LockoutEndDateUtc = null;
                user.LastLoginDate = DateTime.UtcNow;
                this.Update(user);
            }
            catch (Exception)
            {
            }
        }

        public bool TryCreateNewUser(ref ApplicationUser appUser, string password, out IEnumerable<string> errorMessages)
        {
            errorMessages = null;
            IdentityResult addUserResult = this.Create(appUser, password);

            if (!addUserResult.Succeeded)
            {
                errorMessages = addUserResult.Errors;
                return false;
            }

            SendEmailConfirmation(appUser.Id);

            return true;
        }
        public bool TryChangePassword(Guid userId, string newPassword, out IEnumerable<string> error)
        {
            string resetToken = this.GeneratePasswordResetToken(userId);

            return TryChangePassword(userId, resetToken, newPassword, out error);
        }
        public bool TryChangePassword(Guid userId, string resetToken, string newPassword, out IEnumerable<string> error)
        {
            error = null;
            var user = this.FindById(userId);

            if (user == null || string.IsNullOrEmpty(newPassword)) return false;
            else if (this.CheckPassword(user, newPassword)) return true;
            
            var passwordChangeResult = this.ResetPassword(userId, resetToken, newPassword);

            if (passwordChangeResult.Succeeded)
            {
                user.LastPasswordChangedDate = DateTime.UtcNow;
                this.Update(user);
                this.UpdateSecurityStamp(user.Id);

                return true;
            }

            error = passwordChangeResult.Errors;
            return false;
        }
        public void UpdateUserInfo(Guid userId, string firstName, string lastName, string email)
        {
            var user = this.FindById(userId);

            if (user != null)
            {
                if(!string.IsNullOrEmpty(firstName))
                    user.FirstName = firstName;
                if (!string.IsNullOrEmpty(lastName))
                    user.LastName = lastName;
                if (!string.IsNullOrEmpty(email))
                {
                    user.Email = email;
                    user.LoweredEmail = email.ToLower();
                }

                this.Update(user);
            }
        }
        public void DeleteUser(Guid userId)
        {
            var user = this.FindById(userId);

            if (user != null)
                this.Delete(user);
        }
        public ApplicationUserLevel GetUserLevel(Guid userId)
        {
            var user = this.FindById(userId);

            if (user != null)
                return (ApplicationUserLevel)user.Level;

            return ApplicationUserLevel.None;
        }
        public void SendEmailConfirmation(Guid userId)
        {
            SendEmailConfirmation(userId, requestBaseUrl);
        }
        public void SendEmailConfirmation(Guid userId, string baseUrl)
        {
            var userLevel = GetUserLevel(userId);

            if (userLevel == ApplicationUserLevel.None) return;

            string code = this.GenerateEmailConfirmationToken(userId);
            code = code.Base64ForUrlEncode();

            var user = this.FindById(userId);
            var callbackUrl = string.Format("{0}/ConfirmEmail.aspx?userId={1}&code={2}", baseUrl, userId, code);
            var timestamp = string.Format("{0:MMMM d, yyyy - hh:mmtt} {1}", DateTime.Now, DateTime.Now.IsDaylightSavingTime() ? "EDT" : "EST");
            var body = GetFilledTemplate(_welcomeEmailTemplates[userLevel], baseUrl, callbackUrl, timestamp, user.Email);

            this.SendEmail(userId, "Confirm your Silent Passenger® account", body);
        }
        public async Task SendLockoutEmailAsync(Guid userId, DateTime lockoutDateUtc)
        {
            await SendLockoutEmailAsync(userId, lockoutDateUtc, requestBaseUrl);
        }
        public async Task SendLockoutEmailAsync(Guid userId, DateTime lockoutDateUtc, string baseUrl)
        {
            var code = this.GeneratePasswordResetToken(userId);
            code = code.Base64ForUrlEncode();

            var user = this.FindById(userId);
            var localTimestamp = lockoutDateUtc.ToLocalTime();
            var strLockoutDate = string.Format("{0:MMMM d, yyyy - hh:mmtt} {1}", localTimestamp, localTimestamp.IsDaylightSavingTime() ? "EDT" : "EST");
            var callbackUrl = string.Format("{0}/PasswordReset.aspx?userId={1}&code={2}", baseUrl, userId, code);

            var body = GetFilledTemplate("VTS.Membership.AuthServer.Content.AccountLockOutEmail.htm", baseUrl, callbackUrl, strLockoutDate, user.Email);

            await SendEmailAsync(userId, "Silent Passenger® account has been temporarily suspended", body);
        }
        public bool TrySendPasswordResetLink(string email)
        {
            var user = this.FindByEmail(email);
            if (user == null || !(this.IsEmailConfirmed(user.Id)))
            {
                return false;
            }

            return TrySendPasswordResetLink(user.Id, requestBaseUrl);
        }
        public bool TrySendPasswordResetLink(Guid userId, string baseUrl)
        {
            var code = this.GeneratePasswordResetToken(userId);
            code = code.Base64ForUrlEncode();

            baseUrl = "https://app.silentpassenger.com"; // Temporarily override baseUrl

            var user = this.FindById(userId);
            var callbackUrl = string.Format("{0}/PasswordReset.aspx?userId={1}&code={2}", baseUrl, userId, code);
            var timestamp = string.Format("{0:MMMM d, yyyy - hh:mmtt} {1}", DateTime.Now, DateTime.Now.IsDaylightSavingTime() ? "EDT" : "EST");
            var body = GetFilledTemplate("VTS.Membership.AuthServer.Content.PasswordResetEmail.htm", baseUrl, callbackUrl, timestamp, user.Email);

            this.SendEmail(userId, "Silent Passenger® password reset request", body);

            return true;
        }
        public IEnumerable<TrackerEnabledDbContext.Common.Models.AuditLog> GetAuditLog(Guid userId, DateTime? logDate)
        {
            var context = ((ApplicationUserStore)base.Store).Context as ApplicationDbContext;

            IQueryable<TrackerEnabledDbContext.Common.Models.AuditLog> logs = context.GetLogs<ApplicationUser>(userId);
            var q = from l in logs
                    join u in context.Users on l.UserName equals u.Id.ToString() into j
                    from u in j.DefaultIfEmpty()
                    select new { l, u };

            foreach (var item in q)
            {
                item.l.UserName = item.u != null ? item.u.UserName : "Anonymous";
            }

            return q.Select(o => o.l).OrderByDescending(l => l.EventDateUTC).ToList();
        }
        public void UnlockUser(Guid userId)
        {
            AsyncHelpers.RunSync(() => UnlockUserAsync(userId));
        }
        public async Task UnlockUserAsync(Guid userId)
        {
            var user = await FindByIdAsync(userId);
            if (user != null)
            {
                user.LockoutEndDateUtc = null;
                user.AccessFailedCount = 0;

                await UpdateAsync(user);
            }
        }
        public async Task<bool> IsUserApprovedAsync(Guid userId)
        {
            var store = Store as ApplicationUserStore;
            if (store == null)
            {
                throw new ArgumentNullException("store");
            }

            return await store.GetIsApprovedAsync(userId);
        }
        public bool IsUserApproved(Guid userId)
        {
            return AsyncHelpers.RunSync(() => IsUserApprovedAsync(userId));
        }
        public void SetUserApproved(Guid userId, bool approved)
        {
            var user = this.FindById(userId);

            if (user != null)
            {
                user.IsApproved = approved;
                this.Update(user);
            }
        }
        public void UpdateLastActivity(Guid userId)
        {
            var user = this.FindById(userId);
            if (user != null)
            {
                user.LastActivityDate = DateTime.UtcNow;
                this.Update(user);
            }
        }

        public async Task TestEmailTemplatesAsync(Guid userId, string baseUrl)
        {
            string code = this.GenerateEmailConfirmationToken(userId);
            code = code.Base64ForUrlEncode();

            var user = this.FindById(userId);
            var callbackUrl = string.Format("{0}/ConfirmEmail.aspx?userId={1}&code={2}", baseUrl, userId, code);
            var timestamp = string.Format("{0:MMMM d, yyyy - hh:mmtt} {1}", DateTime.Now, DateTime.Now.IsDaylightSavingTime() ? "EDT" : "EST");

            foreach (var template in _welcomeEmailTemplates)
            {
                var body = GetFilledTemplate(template.Value, baseUrl, callbackUrl, timestamp, user.Email);

                this.SendEmail(userId, "Confirm your account", body);
            }

            TrySendPasswordResetLink(userId, baseUrl);
            await SendLockoutEmailAsync(userId, DateTime.UtcNow, baseUrl);
        }

        #region Private Methods
        private string GetFilledTemplate(string resourcePath, string websiteRoot, string callbackUrl, string timestamp, string userEmail)
        {
            string retVal = string.Empty;
            Assembly _assembly = Assembly.GetExecutingAssembly();

            using (StreamReader sr = new StreamReader(_assembly.GetManifestResourceStream(resourcePath)))
            {
                // Read the stream to a string, and write the string to the console.
                string template = sr.ReadToEnd();
                //retVal = string.Format(template, websiteRoot, callbackUrl, now);

                retVal = template.FormatWith(new
                {
                    baseUrl = websiteRoot,
                    callbackUrl
                });
            }

            return InjectIntoMaster(retVal, timestamp, userEmail);
        }
        private string InjectIntoMaster(string htmlContent, string timestamp, string userEmail)
        {
            string retVal = string.Empty;
            Assembly _assembly = Assembly.GetExecutingAssembly();

            using (StreamReader sr = new StreamReader(_assembly.GetManifestResourceStream("VTS.Membership.AuthServer.Content.EmailTemplate.htm")))
            {
                // Read the stream to a string, and write the string to the console.
                string template = sr.ReadToEnd();
                //retVal = string.Format(template, websiteRoot, callbackUrl, now);

                retVal = template.FormatWith(new
                {
                    content = htmlContent,
                    timestamp = timestamp,
                    userEmail = userEmail
                });
            }

            return retVal;
        }
        private async Task<IEnumerable<ApplicationUser>> GetUsersInRole(string roleName, ApplicationRoleManager roleManager)
        {
            var retVal = new List<VTS.Business.OfficeUser>();
            var role = roleManager.FindByName(roleName).Users.First();

            return await Task.FromResult(Users.Where(u => u.Roles.Select(r => r.RoleId).Contains(role.RoleId)).ToList());
        }
        #endregion

        */
    }
}