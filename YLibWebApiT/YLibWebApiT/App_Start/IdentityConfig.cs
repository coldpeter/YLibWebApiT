using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using YLibWebApiT.Models;
using System.Security.Claims;
using System.Web;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OAuth;
using System;

namespace YLibWebApiT
{
    // 配置此应用程序中使用的应用程序用户管理器。UserManager 在 ASP.NET Identity 中定义，并由此应用程序使用。

    public class ApplicationUserManager : UserManager<ApplicationUser>
    {
        public ApplicationUserManager(IUserStore<ApplicationUser> store)
            : base(store)
        {
        }

        public static ApplicationUserManager Create(IdentityFactoryOptions<ApplicationUserManager> options, IOwinContext context)
        {
            var manager = new ApplicationUserManager(new UserStore<ApplicationUser>(context.Get<ApplicationDbContext>()));
            // 配置用户名的验证逻辑
            manager.UserValidator = new UserValidator<ApplicationUser>(manager)
            {
                AllowOnlyAlphanumericUserNames = false,
                RequireUniqueEmail = true
            };
            // 配置密码的验证逻辑
            manager.PasswordValidator = new PasswordValidator
            {
                RequiredLength = 6,
                RequireNonLetterOrDigit = true,
                RequireDigit = true,
                RequireLowercase = true,
                RequireUppercase = true,
            };
            var dataProtectionProvider = options.DataProtectionProvider;
            if (dataProtectionProvider != null)
            {
                manager.UserTokenProvider = new DataProtectorTokenProvider<ApplicationUser>(dataProtectionProvider.Create("ASP.NET Identity"));
            }
            return manager;
        }

        public override Task<ApplicationUser> FindAsync(string userName, string password)
        {
            //测试
            if (userName == "admin" && password == "admin")
            {
                var user = new ApplicationUser()
                {
                    UserName = "admin",
                    Id = "1",
                };
                return Task.FromResult<ApplicationUser>(user);

            }
            else
                return null;
          //  return base.FindAsync(userName, password);
        }
    }

    class AuthorizedUser : IDisposable
    {
        private AuthorizedUser()
        {
        }

        /// <summary>
        /// 当前登录用户
        /// </summary>
        public ApplicationUser User
        {
            get
            {
                var user = (ClaimsIdentity)HttpContext.Current.GetOwinContext()?.Authentication?.User?.Identity;
                if (user == null) return null;
                if (user.GetUserId().IsNullOrEmpty()) return null;
                return user.FindFirstValue("SPS_User").JsonDeserialize<AccountModel>();
            }
        }
        /// <summary>
        /// 客户端ID
        /// </summary>
        public String ClientId
        {
            get
            {
                var context = HttpContext.Current?.GetOwinContext();
                if (context == null)
                    return null;


                var user = (ClaimsIdentity)context?.Authentication?.User?.Identity;
                if (user != null)
                    return user.FindFirstValue("SPS_Client");

                var clietId = context?.Get<string>("as:client_id");
                return clietId;

            }
        }
        //private static AuthorizedUser _current = null;
        public static AuthorizedUser Current
        {
            get
            {
                //通过用户登录标识，获取用户跟权限有关的对象
                //var user = (new AuthoirzedUserManager()).GetByUserName();
                return HttpContext.Current.GetOwinContext()?.Get<AuthorizedUser>();// _current ?? (_current = new AuthorizedUser());
            }
        }

        public static AuthorizedUser Create()
        {
            return new AuthorizedUser();
        }
        /// <summary>
        /// 退出系统
        /// </summary>
        public static void LoginOut()
        {
            var auth = HttpContext.Current.GetOwinContext()?.Authentication;
            if (auth == null) return;
            auth.SignOut(CookieAuthenticationDefaults.AuthenticationType);
            auth.SignOut(OAuthDefaults.AuthenticationType);
            //HttpContext.Current.GetOwinContext().Authentication.SignOut(OAuthAuthorizationOptions.AuthenticationType);
        }


        public void Dispose()
        {


        }
    }
}
