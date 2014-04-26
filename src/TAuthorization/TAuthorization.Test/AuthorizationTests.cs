using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace TAuthorization.Test
{
    [TestClass]
    public class AuthorizationTests
    {
        private readonly TestAuthorizationDataStore _store;
        public AuthorizationTests()
        {
            _store = new TestAuthorizationDataStore();
        }

        private IList<Claim> ClaimsProvider(string username)
        {
            if (username.ToLower() == Thread.CurrentPrincipal.Identity.Name.ToLower())
            {
                return new Claim[] { new Claim(ClaimTypes.Role, "RoleName"), new Claim(ClaimTypes.Role, "RoleName3") };
            }
            else
            {
                return new Claim[] { };
            }
        }

        [TestMethod]
        public void CanGrantAccessForAnAction()
        {
            var authorization = new Authorization(_store, ClaimsProvider);
            authorization.GrantAccess("ActionName", "RoleName");
            var permission =
                authorization.Query()
                    .SingleOrDefault(
                        ep =>
                            ep.Action == "ActionName" &&
                            ep.RoleName == "RoleName");

            if (permission != null) Assert.AreEqual(permission.Permission, Permission.Grant);
        }

        [TestMethod]
        public void CanGrantAccessForAnActionWithParameters()
        {
            var authorization = new Authorization(_store, ClaimsProvider);
            var param1 = new ActionParam1 { P1 = "P1Value", Owner = "OwnerValue" };
            authorization.GrantAccess("ActionName", "RoleName", param1);
            var permissions = authorization.Query<ActionParam1>("ActionName")
                 .Where(ep => ep.ActionParameters.P1 == "P1Value" && ep.ActionParameters.Owner == "OwnerValue").ToList();

            Assert.AreEqual(permissions[0].ActionParameters.P1, "P1Value");
        }

        [TestMethod]
        public void CanGrantAccessForAnActionAndEntityId()
        {
            var authorization = new Authorization(_store, ClaimsProvider);
            var eGuid = Guid.NewGuid().ToString();
            authorization.GrantAccess("ActionName", "RoleName", eGuid);
            var permission =
                authorization.Query()
                    .SingleOrDefault(
                        ep =>
                            ep.EntityId == eGuid && ep.Action == "ActionName" &&
                            ep.RoleName == "RoleName");
            if (permission != null) Assert.AreEqual(permission.Permission, Permission.Grant);
        }

        [TestMethod]
        public void CanGrantAccessForAnActionAndEntityIdWithParameters()
        {
            var authorization = new Authorization(_store, ClaimsProvider);
            var eGuid = Guid.NewGuid().ToString();
            var param1 = new ActionParam1 { P1 = "P1Value", Owner = "OwnerValue" };
            authorization.GrantAccess("ActionName", "RoleName", eGuid, param1);
            var permissions = authorization.Query<ActionParam1>("ActionName")
                .Where(
                    ep =>
                        ep.EntityId == eGuid && ep.ActionParameters.P1 == "P1Value" &&
                        ep.ActionParameters.Owner == "OwnerValue").ToList();
            Assert.AreEqual(permissions[0].ActionParameters.P1, "P1Value");
        }

        [TestMethod]
        public void CanDenyAccessForAnAction()
        {
            var authorization = new Authorization(_store, ClaimsProvider);
            authorization.DenyAccess("ActionName", "RoleName");
            var permission =
                 authorization.Query()
                     .SingleOrDefault(
                         ep =>
                             ep.Action == "ActionName" &&
                             ep.RoleName == "RoleName");
            if (permission != null) Assert.AreEqual(permission.Permission, Permission.Deny);
        }

        [TestMethod]
        public void CanDenyAccessForAnActionWithParameters()
        {
            var authorization = new Authorization(_store, ClaimsProvider);
            var param1 = new ActionParam1 { P1 = "P1Value", Owner = "OwnerValue" };
            authorization.DenyAccess("ActionName", "RoleName", param1);
            var permissions = authorization.Query<ActionParam1>("ActionName")
                 .Where(ep => ep.ActionParameters.P1 == "P1Value" && ep.ActionParameters.Owner == "OwnerValue").ToList();

            Assert.AreEqual(permissions[0].ActionParameters.P1, "P1Value");
        }

        [TestMethod]
        public void CanDenyAccessForAnActionAndEntityId()
        {
            var authorization = new Authorization(_store, ClaimsProvider);
            var eGuid = Guid.NewGuid().ToString();
            authorization.DenyAccess("ActionName", "RoleName", eGuid);
            var permission =
                authorization.Query()
                    .SingleOrDefault(
                        ep =>
                            ep.EntityId == eGuid && ep.Action == "ActionName" &&
                            ep.RoleName == "RoleName");
            if (permission != null) Assert.AreEqual(permission.Permission, Permission.Deny);
        }

        [TestMethod]
        public void CanDenyAccessForAnActionAndEntityIdWithParameters()
        {
            var authorization = new Authorization(_store, ClaimsProvider);
            var eGuid = Guid.NewGuid().ToString();
            var param1 = new ActionParam1 { P1 = "P1Value", Owner = "OwnerValue" };
            authorization.DenyAccess("ActionName", "RoleName", eGuid, param1);
            var permissions = authorization.Query<ActionParam1>("ActionName")
                .Where(
                    ep =>
                        ep.EntityId == eGuid && ep.ActionParameters.P1 == "P1Value" &&
                        ep.ActionParameters.Owner == "OwnerValue").ToList();
            Assert.AreEqual(permissions[0].ActionParameters.P1, "P1Value");
        }

        [TestMethod]
        public void CanQueryOnEntityPermissionsWithEntityId()
        {
            var authorization = new Authorization(_store, ClaimsProvider);
            var eGuid = Guid.NewGuid().ToString();
            authorization.GrantAccess("ActionName", "RoleName", eGuid);

            var permission = authorization.Query().SingleOrDefault(ep => ep.EntityId == eGuid);
            if (permission != null) Assert.AreEqual((object)permission.EntityId, eGuid);
        }

        [TestMethod]
        public void CanQueryOnEntityPermissionsWithRoleName()
        {
            var authorization = new Authorization(_store, ClaimsProvider);
            var eGuid = Guid.NewGuid().ToString();
            authorization.GrantAccess("ActionName", "RoleName", eGuid);

            var permission =
                authorization.Query()
                    .SingleOrDefault(ep => ep.Action == "ActionName" &&
                                           ep.RoleName == "RoleName");
            if (permission != null) Assert.AreEqual((object)permission.EntityId, eGuid);
        }

        [TestMethod]
        public void CanQueryOnEntityPermissionsWithActionParameters()
        {
            var authorization = new Authorization(_store, ClaimsProvider);
            var param1 = new ActionParam1 { P1 = "P1Value", Owner = "OwnerValue" };
            authorization.GrantAccess("ActionName", "RoleName", param1);

            var permissions = authorization.Query<ActionParam1>("ActionName")
                .Where(ep => ep.ActionParameters.P1 == "P1Value" && ep.ActionParameters.Owner == "OwnerValue").ToList();
            Assert.AreEqual(permissions[0].ActionParameters.P1, "P1Value");
        }

        [TestMethod]
        public void CanClearPermissionsForAnAction()
        {
            var authorization = new Authorization(_store, ClaimsProvider);
            //authorization.ClearPermissions("ActionName");
            authorization.ClearPermissions(ep => ep.Action == "ActioName");
            var permissionCount =
                authorization.Query()
                    .Count(ep => ep.Action == "ActionName");
            Assert.AreEqual(permissionCount, 0);
        }

        [TestMethod]
        public void CanClearPermissionsForAnEntityId()
        {
            var authorization = new Authorization(_store, ClaimsProvider);
            var eGuid = Guid.NewGuid().ToString();
            authorization.ClearPermissions(ep => ep.EntityId == eGuid);
            var permissionCount = authorization.Query().Count(ep => ep.EntityId == eGuid);
            Assert.AreEqual(permissionCount, 0);
        }

        [TestMethod]
        public void CanClearPermissionsForActionAndEntityId()
        {
            var authorization = new Authorization(_store, ClaimsProvider);
            var eGuid = Guid.NewGuid().ToString();
            authorization.ClearPermissions(
                ep => ep.Action == "ActioName" && ep.EntityId == eGuid);
            var permissionCount =
                authorization.Query()
                    .Count(
                        ep =>
                            ep.Action == "ActionName" &&
                            ep.EntityId == eGuid);
            Assert.AreEqual(permissionCount, 0);
        }

        [TestMethod]
        public void CanGetPermissionForUser()
        {
            var authorization = new Authorization(_store, ClaimsProvider);
            authorization.GrantAccess("Action", "RoleName");
            var perm = authorization.GetPermission("Action", null, Thread.CurrentPrincipal.Identity.Name);
            Assert.AreEqual(Permission.Grant, perm);
        }

        [TestMethod]
        public void CanGetPermissionForCurrentUser()
        {
            var authorization = new Authorization(_store, ClaimsProvider);
            authorization.GrantAccess("Action", "RoleName");
            authorization.GrantAccess("Action", "RoleName2");
            var perm = authorization.GetPermission("Action");
            Assert.AreEqual(Permission.Grant, perm);
        }

        [TestMethod]
        public void ReturnsNonePermissionForCaseThatThereAreNotAnyPermissionsForUser()
        {
            var authorization = new Authorization(_store, ClaimsProvider);
            authorization.GrantAccess("Action", "RoleName");
            authorization.GrantAccess("Action", "RoleName3");
            var perm = authorization.GetPermission("Action1");
            Assert.AreEqual(Permission.None, perm);
        }

        [TestMethod]
        public void ReturnsDenyForCaseThatThereAreJustDenyInPermissionsForUser()
        {
            var authorization = new Authorization(_store, ClaimsProvider);
            authorization.DenyAccess("Action", "RoleName");
            authorization.DenyAccess("Action", "RoleName3");
            var perm = authorization.GetPermission("Action");
            Assert.AreEqual(Permission.Deny, perm);
        }

        [TestMethod]
        public void ReturnsGrantForCaseThatThereAreAtLeastOneGrantInPermissionsForUser()
        {
            var authorization = new Authorization(_store, ClaimsProvider);
            authorization.GrantAccess("Action", "RoleName");
            authorization.DenyAccess("Action", "RoleName3");
            var perm = authorization.GetPermission("Action");
            Assert.AreEqual(Permission.Grant, perm);
        }
        //[TestMethod]
        //public void CanQueryOverPermissionsForUser()
        //{
        //    var authorization = new Authorization(_store, ClaimsProvider);
        //    authorization.GrantAccess("ActionName", "role1");
        //    var permissions = authorization.GetUserPermissions("Username")
        //        .Where(ep => ep.ActionName == "ActionName").ToList();
        //    Assert.IsTrue(permissions.Any(ep => ep.RoleName == "role1" && ep.Permission == Permission.Grant));
        //}

        //[TestMethod]
        //public void CanGetSpecificPermissionForUser()
        //{
        //    var authorization = new Authorization(_store);
        //    authorization.GrantAccess("ActionName", "role1");
        //    var permission = authorization.GetUserPermission("Username", "ActionName");
        //    Assert.IsTrue(permission == Permission.Grant);
        //}
    }

    public class ActionParam1
    {
        public string P1 { get; set; }
        public string Owner { get; set; }
    }
}
