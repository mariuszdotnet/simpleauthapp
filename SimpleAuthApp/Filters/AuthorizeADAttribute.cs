using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.DirectoryServices.AccountManagement;

namespace SimpleAuthApp.Filters
{
    public class AuthorizeADAttribute : AuthorizeAttribute
    {
        public string Groups { get; set; }
        protected override bool AuthorizeCore(HttpContextBase httpContext)
        {
            if (base.AuthorizeCore(httpContext))
            {
                /* Return true immediately if the authorization is not 
                locked down to any particular AD group */
                if (String.IsNullOrEmpty(Groups))
                    return true;

                // Get the AD groups
                var groups = Groups.Split(',').ToList();

                // Verify that the user is in the given AD group (if any)

                //Set up the domain context
                var groupContext = new PrincipalContext(ContextType.Domain, "northamerica", "OU=UserAccounts,DC=redmond,DC=corp,DC=microsoft,DC=com");
                var userContext = new PrincipalContext(ContextType.Domain, "northamerica");

                // Find the user
                var userPrincipal = UserPrincipal.FindByIdentity(userContext, IdentityType.SamAccountName, httpContext.User.Identity.Name);

                // find the group in question
                //GroupPrincipal myGroup = GroupPrincipal.FindByIdentity(groupContext, "Cdn-Microsoft Canada Co");              
                try
                {
                    foreach (var group in groups)
                        if (userPrincipal.IsMemberOf(groupContext, IdentityType.Name, group))
                        {
                            Constants.UserGroup = group;
                            return true;
                        }
                }
                catch (NoMatchingPrincipalException e)
                {
                    Console.WriteLine("{0} Exception caught.", e);
                }
            }
            return false;
        }

        protected override void HandleUnauthorizedRequest(
        AuthorizationContext filterContext)
        {
            if (filterContext.HttpContext.User.Identity.IsAuthenticated)
            {
                var result = new ViewResult();
                result.ViewName = "Index";
                filterContext.Result = result;
            }
            else
                base.HandleUnauthorizedRequest(filterContext);
        }
    }
}