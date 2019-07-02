using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Web;
using System.Web.Http;
using System.Web.Http.Controllers;
using System.Web.Http.Filters;

namespace YLibWebApiT.Filters
{
    public class BasicActionAuthenticationAttribute:ActionFilterAttribute
    {
        public override void OnActionExecuting(HttpActionContext actionContext)
        {
            if (actionContext.ActionDescriptor.GetCustomAttributes<AllowAnonymousAttribute>().Any())
            {
                base.OnActionExecuting(actionContext);
            }
            else
            {
                var user =  (ClaimsIdentity)HttpContext.Current.GetOwinContext()?.Authentication?.User?.Identity; ;
                if (user == null)
                {
                    //未验证（登录）的用户, 而且是非匿名访问，则转向登录页面  
                    //HttpContext.Current.Response.Redirect("~/Account/Login", true);
                    actionContext.Response =
                        actionContext.Request.CreateErrorResponse(HttpStatusCode.Unauthorized, new HttpError("用户未登录"));
                    AuthorizedUser.LoginOut();
                    return;
                }
                else
                {
                    //没有配置权限策略
                    base.OnActionExecuting(actionContext);

                }

            }
        }
    }
}