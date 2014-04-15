using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;

namespace TAuthorization
{
    public class Authorization
    {
        private IAuthorizationDataStore _dataStore;

        public Authorization(IAuthorizationDataStore dataStore)
        {
            _dataStore = dataStore;
        }

        public virtual IQueryable<EntityPermission> Query()
        {
            return _dataStore.Query();
        }

        public virtual IQueryable<EntityPermission> Query(string actionCategory, string actionName)
        {
            return Query().Where(ep => ep.ActionCategory == actionCategory && ep.ActionName == actionName);
        }

        public virtual IEnumerable<EntityPermission<TActionParamsType>> Query<TActionParamsType>(string actionCategory, string actionName) where TActionParamsType : new()
        {
            var entityPermisions = Query(actionCategory, actionName).ToList();
            var result = new List<EntityPermission<TActionParamsType>>();

            var type = typeof(TActionParamsType);

            foreach (var entityPermission in entityPermisions)
            {
                var permsStr = new EntityPermission<TActionParamsType>
                {
                    EntityId = entityPermission.EntityId,
                    Id = entityPermission.Id,
                    ActionName = entityPermission.ActionName,
                    ActionCategory = entityPermission.ActionCategory,
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

        public virtual EntityPermission GrantAccess(string actionCategory, string actionName, string roleName)
        {
            return GrantAccess(actionCategory, actionName, roleName, Guid.Empty);
        }

        public virtual EntityPermission GrantAccess(string actionCategory, string actionName, string roleName, Guid entityId)
        {
            EntityPermission entityPermission =
                Query().SingleOrDefault(ep => ep.ActionName == actionName && ep.ActionCategory == actionCategory &&
                                              ep.RoleName == roleName && ep.EntityId == entityId);
            if (entityPermission == null)
            {
                var ep = new EntityPermission
                {
                    ActionName = actionName,
                    ActionCategory = actionCategory,
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
            return entityPermission;
        }

        public virtual EntityPermission GrantAccess<TActionParamsType>(string actionCategory, string actionName, string roleName, TActionParamsType T) where TActionParamsType : new()
        {
            return GrantAccess(actionCategory, actionName, roleName, Guid.Empty, T);
        }

        public virtual EntityPermission GrantAccess<TActionParamsType>(string actionCategory, string actionName, string roleName, Guid entityId, TActionParamsType T) where TActionParamsType : new()
        {
            var entityPermission =
                Query().SingleOrDefault(ep => ep.ActionName == actionName && ep.ActionCategory == actionCategory &&
                                              ep.RoleName == roleName && ep.EntityId == entityId);
            if (entityPermission == null)
            {
                var ep = new EntityPermission
                {
                    ActionName = actionName,
                    ActionCategory = actionCategory,
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
            return entityPermission;
        }

        public virtual EntityPermission DenyAccess(string actionCategory, string actionName, string roleName)
        {
            return DenyAccess(actionCategory, actionName, roleName, Guid.Empty);
        }

        public virtual EntityPermission DenyAccess(string actionCategory, string actionName, string roleName, Guid entityId)
        {
            var entityPermission =
                Query().SingleOrDefault(ep => ep.ActionName == actionName && ep.ActionCategory == actionCategory &&
                                              ep.RoleName == roleName && ep.EntityId == entityId);
            if (entityPermission == null)
            {
                var ep = new EntityPermission
                {
                    ActionName = actionName,
                    ActionCategory = actionCategory,
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
            return entityPermission;
        }

        public virtual EntityPermission DenyAccess<TActionParamsType>(string actionCategory, string actionName, string roleName, TActionParamsType T) where TActionParamsType : new()
        {
            return GrantAccess(actionCategory, actionName, roleName, Guid.Empty, T);
        }

        public virtual EntityPermission DenyAccess<TActionParamsType>(string actionCategory, string actionName, string roleName, Guid entityId, TActionParamsType T) where TActionParamsType : new()
        {
            var entityPermission =
                Query().SingleOrDefault(ep => ep.ActionName == actionName && ep.ActionCategory == actionCategory &&
                                              ep.RoleName == roleName && ep.EntityId == entityId);
            if (entityPermission == null)
            {
                var ep = new EntityPermission
                {
                    ActionName = actionName,
                    ActionCategory = actionCategory,
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
            return entityPermission;
        }

        public virtual void ClearPermissions(Func<EntityPermission, bool> predicate)
        {
            var entityPermissions = _dataStore.Query().Where(predicate).ToList();
            _dataStore.Delete(entityPermissions);
        }


    }
}
