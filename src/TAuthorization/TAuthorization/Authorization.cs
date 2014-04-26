﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Security.Claims;
using System.Threading;

namespace TAuthorization
{
    public class Authorization
    {
        private IAuthorizationDataStore _dataStore;
        private Func<string, IList<Claim>> _claimsProvider;

        public Authorization(IAuthorizationDataStore dataStore, Func<string, IList<Claim>> claimsProvider)
        {
            _dataStore = dataStore;
            _claimsProvider = claimsProvider;
        }

        public virtual IQueryable<EntityPermission> Query()
        {
            return _dataStore.Query();
        }

        public virtual Permission GetPermission(string action, string entityId = null, string username = null)
        {
            var q = Query().Where(ep => ep.Action == action);
            if (username != null)
            {
                var roles = _claimsProvider(username).Where(c => c.Type == ClaimTypes.Role).Select(c => c.Value).ToList();
                q = q.Where(ep => roles.Contains(ep.RoleName));
            }
            if (entityId != null)
            {
                q = q.Where(ep => ep.EntityId == entityId);
            }
            var res = q.SingleOrDefault();
            if (res == null)
                return Permission.None;
            return res.Permission;
        }

        //public virtual IQueryable<EntityPermission> Query(string actionName)
        //{
        //    return Query().Where(ep => ep.ActionName == actionName);
        //}

        public virtual IEnumerable<EntityPermission<TActionParamsType>> Query<TActionParamsType>(string action, string username = null) where TActionParamsType : new()
        {
            var entityPermisions = Query().Where(ep => ep.Action == action);
            if (username != null)
            {
                var roles = _claimsProvider(username).Where(c => c.Type == ClaimTypes.Role).Select(c => c.Value).ToList();
                entityPermisions = entityPermisions.Where(ep => roles.Contains(ep.RoleName));
            }
            var result = new List<EntityPermission<TActionParamsType>>();

            var type = typeof(TActionParamsType);

            foreach (var entityPermission in entityPermisions)
            {
                var permsStr = new EntityPermission<TActionParamsType>
                {
                    EntityId = entityPermission.EntityId,
                    Id = entityPermission.Id,
                    Action = entityPermission.Action,
                    RoleName = entityPermission.RoleName,
                    Permission = entityPermission.Permission,
                    ActionParameters = new TActionParamsType()
                };
                foreach (var rawActionParam in entityPermission.RawActionParams)
                {
                    var prop = type.GetProperty(rawActionParam.Key);
                    if (null != prop && prop.CanWrite)
                        prop.SetValue(permsStr.ActionParameters, rawActionParam.Value);
                }
                result.Add(permsStr);
            }
            return result;
        }

        public virtual void GrantAccess(string actionName, string roleName, string entityId)
        {
            EntityPermission entityPermission =
                Query().SingleOrDefault(ep => ep.Action == actionName &&
                                              ep.RoleName == roleName && ep.EntityId == entityId);
            if (entityPermission == null)
            {
                var ep = new EntityPermission
                {
                    Action = actionName,
                    EntityId = entityId,
                    RoleName = roleName,
                    Permission = Permission.Grant
                };
                _dataStore.Insert(ep);
            }
            else
            {
                if (entityPermission.Permission != Permission.Grant)
                {
                    entityPermission.Permission = Permission.Grant;
                    _dataStore.Update(entityPermission);
                }
            }
        }

        public virtual void GrantAccess(string actionName, string roleName)
        {
            GrantAccess(actionName, roleName, Guid.Empty);
        }

        public virtual void GrantAccess<TActionParamsType>(string actionName, string roleName, TActionParamsType T) where TActionParamsType : new()
        {
            GrantAccess(actionName, roleName, null, T);
        }

        public virtual void GrantAccess<TActionParamsType>(string actionName, string roleName, string entityId, TActionParamsType T) where TActionParamsType : new()
        {
            var entityPermission =
                Query().SingleOrDefault(ep => ep.Action == actionName && ep.RoleName == roleName && ep.EntityId == entityId);
            if (entityPermission == null)
            {
                var ep = new EntityPermission
                {
                    Action = actionName,
                    EntityId = entityId,
                    RoleName = roleName,
                    Permission = Permission.Grant,
                };

                var type = typeof(TActionParamsType);
                PropertyInfo[] propertyInfos = type.GetProperties();
                foreach (var propertyInfo in propertyInfos)
                {
                    ep.RawActionParams.Add(propertyInfo.Name, propertyInfo.GetValue(T).ToString());
                }
                _dataStore.Insert(ep);
            }
            else
            {
                if (entityPermission.Permission != Permission.Grant)
                {
                    entityPermission.Permission = Permission.Grant;
                    _dataStore.Update(entityPermission);
                }
            }
        }

        public virtual void DenyAccess(string actionName, string roleName)
        {
            DenyAccess(actionName, roleName, null);
        }

        public virtual void DenyAccess(string actionName, string roleName, string entityId)
        {
            var entityPermission =
                Query().SingleOrDefault(ep => ep.Action == actionName &&
                                              ep.RoleName == roleName && ep.EntityId == entityId);
            if (entityPermission == null)
            {
                var ep = new EntityPermission
                {
                    Action = actionName,
                    EntityId = entityId,
                    RoleName = roleName,
                    Permission = Permission.Deny
                };
                _dataStore.Insert(ep);
            }
            else
            {
                if (entityPermission.Permission != Permission.Deny)
                {
                    entityPermission.Permission = Permission.Deny;
                    _dataStore.Update(entityPermission);
                }
            }
        }

        public virtual void DenyAccess<TActionParamsType>(string actionName, string roleName, TActionParamsType T) where TActionParamsType : new()
        {
            GrantAccess(actionName, roleName, null, T);
        }

        public virtual void DenyAccess<TActionParamsType>(string actionName, string roleName, string entityId, TActionParamsType T) where TActionParamsType : new()
        {
            var entityPermission =
                Query().SingleOrDefault(ep => ep.Action == actionName &&
                                              ep.RoleName == roleName && ep.EntityId == entityId);
            if (entityPermission == null)
            {
                var ep = new EntityPermission
                {
                    Action = actionName,
                    EntityId = entityId,
                    RoleName = roleName,
                    Permission = Permission.Deny,
                };

                var type = typeof(TActionParamsType);
                PropertyInfo[] propertyInfos = type.GetProperties();
                foreach (var propertyInfo in propertyInfos)
                {
                    ep.RawActionParams.Add(propertyInfo.Name, propertyInfo.GetValue(T).ToString());
                }
                _dataStore.Insert(ep);
            }
            else
            {
                if (entityPermission.Permission != Permission.Deny)
                {
                    entityPermission.Permission = Permission.Deny;
                    _dataStore.Update(entityPermission);
                }
            }
        }

        public virtual void ClearPermissions(Func<EntityPermission, bool> predicate)
        {
            var entityPermissions = _dataStore.Query().Where(predicate).ToList();
            _dataStore.Delete(entityPermissions);
        }


    }
}
