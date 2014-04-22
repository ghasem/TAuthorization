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

        [TestMethod]
        public void CanGrantAccessForAnAction()
        {
            var authorization = new Authorization(_store);
            authorization.GrantAccess("ActionCategory", "ActionName", "RoleName");
            var permission =
                authorization.Query()
                    .SingleOrDefault(
                        ep =>
                            ep.ActionName == "ActionName" && ep.ActionCategory == "ActionCategory" &&
                            ep.RoleName == "RoleName");

            if (permission != null) Assert.AreEqual(permission.Permission, Permission.Grant);
        }

        [TestMethod]
        public void CanGrantAccessForAnActionWithParameters()
        {
            var authorization = new Authorization(_store);
            var param1 = new ActionParam1 { P1 = "P1Value", Owner = "OwnerValue" };
            authorization.GrantAccess("ActionCategory", "ActionName", "RoleName", param1);
            var permissions = authorization.Query<ActionParam1>("ActionCategory", "ActionName")
                 .Where(ep => ep.ActionParameters.P1 == "P1Value" && ep.ActionParameters.Owner == "OwnerValue").ToList();

            Assert.AreEqual(permissions[0].ActionParameters.P1, "P1Value");
        }

        [TestMethod]
        public void CanGrantAccessForAnActionAndEntityId()
        {
            var authorization = new Authorization(_store);
            var eGuid = Guid.NewGuid();
            authorization.GrantAccess("ActionCategory", "ActionName", "RoleName", eGuid);
            var permission =
                authorization.Query()
                    .SingleOrDefault(
                        ep =>
                            ep.EntityId == eGuid && ep.ActionName == "ActionName" &&
                            ep.ActionCategory == "ActionCategory" && ep.RoleName == "RoleName");
            if (permission != null) Assert.AreEqual(permission.Permission, Permission.Grant);
        }

        [TestMethod]
        public void CanGrantAccessForAnActionAndEntityIdWithParameters()
        {
            var authorization = new Authorization(_store);
            var eGuid = Guid.NewGuid();
            var param1 = new ActionParam1 {P1 = "P1Value", Owner = "OwnerValue"};
            authorization.GrantAccess("ActionCategory", "ActionName", "RoleName", eGuid, param1);
            var permissions = authorization.Query<ActionParam1>("ActionCategory", "ActionName")
                .Where(
                    ep =>
                        ep.EntityId == eGuid && ep.ActionParameters.P1 == "P1Value" &&
                        ep.ActionParameters.Owner == "OwnerValue").ToList();
            Assert.AreEqual(permissions[0].ActionParameters.P1, "P1Value");
        }

        [TestMethod]
        public void CanDenyAccessForAnAction()
        {
            var authorization = new Authorization(_store);
            authorization.DenyAccess("ActionCategory", "ActionName", "RoleName");
            var permission =
                 authorization.Query()
                     .SingleOrDefault(
                         ep =>
                             ep.ActionName == "ActionName" && ep.ActionCategory == "ActionCategory" &&
                             ep.RoleName == "RoleName");
            if (permission != null) Assert.AreEqual(permission.Permission, Permission.Deny);
        }

        [TestMethod]
        public void CanDenyAccessForAnActionWithParameters()
        {
            var authorization = new Authorization(_store);
            var param1 = new ActionParam1 { P1 = "P1Value", Owner = "OwnerValue" };
            authorization.DenyAccess("ActionCategory", "ActionName", "RoleName", param1);
            var permissions = authorization.Query<ActionParam1>("ActionCategory", "ActionName")
                 .Where(ep => ep.ActionParameters.P1 == "P1Value" && ep.ActionParameters.Owner == "OwnerValue").ToList();

            Assert.AreEqual(permissions[0].ActionParameters.P1, "P1Value");
        }

        [TestMethod]
        public void CanDenyAccessForAnActionAndEntityId()
        {
            var authorization = new Authorization(_store);
            var eGuid = Guid.NewGuid();
            authorization.DenyAccess("ActionCategory", "ActionName", "RoleName", eGuid);
            var permission =
                authorization.Query()
                    .SingleOrDefault(
                        ep =>
                            ep.EntityId == eGuid && ep.ActionName == "ActionName" &&
                            ep.ActionCategory == "ActionCategory" && ep.RoleName == "RoleName");
            if (permission != null) Assert.AreEqual(permission.Permission, Permission.Deny);
        }

        [TestMethod]
        public void CanDenyAccessForAnActionAndEntityIdWithParameters()
        {
            var authorization = new Authorization(_store);
            var eGuid = Guid.NewGuid();
            var param1 = new ActionParam1 { P1 = "P1Value", Owner = "OwnerValue" };
            authorization.DenyAccess("ActionCategory", "ActionName", "RoleName", eGuid, param1);
            var permissions = authorization.Query<ActionParam1>("ActionCategory", "ActionName")
                .Where(
                    ep =>
                        ep.EntityId == eGuid && ep.ActionParameters.P1 == "P1Value" &&
                        ep.ActionParameters.Owner == "OwnerValue").ToList();
            Assert.AreEqual(permissions[0].ActionParameters.P1, "P1Value");
        }



        [TestMethod]
        public void CanQueryOnEntityPermissionsWithEntityId()
        {
            var authorization = new Authorization(_store);
            var eGuid = Guid.NewGuid();           
            authorization.GrantAccess("ActionCategory", "ActionName", "RoleName", eGuid);

            var permission = authorization.Query().SingleOrDefault(ep => ep.EntityId == eGuid);
            if (permission != null) Assert.AreEqual((object)permission.EntityId, eGuid);
        }

        [TestMethod]
        public void CanQueryOnEntityPermissionsWithRoleName()
        {
            var authorization = new Authorization(_store);
            var eGuid = Guid.NewGuid();
            authorization.GrantAccess("ActionCategory", "ActionName", "RoleName", eGuid);

            var permission =
                authorization.Query()
                    .SingleOrDefault(ep => ep.ActionName == "ActionName" && ep.ActionCategory == "ActionCategory" &&
                                           ep.RoleName == "RoleName");
            if (permission != null) Assert.AreEqual((object)permission.EntityId, eGuid);
        }

        [TestMethod]
        public void CanQueryOnEntityPermissionsWithActionParameters()
        {
           var authorization = new Authorization(_store);
           var param1 = new ActionParam1 { P1 = "P1Value", Owner = "OwnerValue" };
           authorization.GrantAccess("ActionCategory", "ActionName", "RoleName", param1);

            var permissions = authorization.Query<ActionParam1>("ActionCategory", "ActionName")
                .Where(ep => ep.ActionParameters.P1 == "P1Value" && ep.ActionParameters.Owner == "OwnerValue").ToList();
            Assert.AreEqual(permissions[0].ActionParameters.P1, "P1Value");
        }

        [TestMethod]
        public void CanClearPermissionsForAnAction()
        {
            var authorization = new Authorization(_store);
            //authorization.ClearPermissions("ActionCategory", "ActionName");
            authorization.ClearPermissions(ep => ep.ActionName == "ActioName" && ep.ActionCategory == "ActionCategory");
            var permissionCount =
                authorization.Query()
                    .Count(ep => ep.ActionName == "ActionName" && ep.ActionCategory == "ActionCategory");
            Assert.AreEqual(permissionCount, 0);
        }

        [TestMethod]
        public void CanClearPermissionsForAnEntityId()
        {
            var authorization = new Authorization(_store);
            var eGuid = Guid.NewGuid();
            authorization.ClearPermissions(ep => ep.EntityId == eGuid);
            var permissionCount = authorization.Query().Count(ep => ep.EntityId == eGuid);
            Assert.AreEqual(permissionCount, 0);
        }

        [TestMethod]
        public void CanClearPermissionsForActionAndEntityId()
        {
            var authorization = new Authorization(_store);
            var eGuid = Guid.NewGuid();
            authorization.ClearPermissions(
                ep => ep.ActionName == "ActioName" && ep.ActionCategory == "ActionCategory" && ep.EntityId == eGuid);
            var permissionCount =
                authorization.Query()
                    .Count(
                        ep =>
                            ep.ActionName == "ActionName" && ep.ActionCategory == "ActionCategory" &&
                            ep.EntityId == eGuid);
            Assert.AreEqual(permissionCount, 0);
        }

        [TestMethod]
        public void CanQueryOverPermissionsForUser()
        {
            var authorization = new Authorization(_store);
            //((ClaimsPrincipal)Thread.CurrentPrincipal)
            Claim
            authorization.GrantAccess("ActionCategory", "ActionName", "role1");
            var permissions = authorization.GetUserPermissions("Username")
                .Where(ep => ep.ActionName == "ActionName" && ep.ActionCategory == "ActionCategory");

        }
    }

    public class ActionParam1
    {
        public string P1 { get; set; }
        public string Owner { get; set; }
    }
}
