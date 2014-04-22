using System;
using System.Collections.Generic;
using System.Linq;

namespace TAuthorization.Test
{
    public class TestAuthorizationDataStore : IAuthorizationDataStore
    {
        private readonly IList<EntityPermission> _entityPermissions;
        public TestAuthorizationDataStore()
        {
            _entityPermissions = new List<EntityPermission>();
        }

        public IQueryable<EntityPermission> Query()
        {
            return _entityPermissions.AsQueryable();
        }

        public void Delete(List<EntityPermission> permissions)
        {
            foreach (var entityPermission in _entityPermissions)
            {
                _entityPermissions.Remove(entityPermission);
            }
        }

        public void Insert(EntityPermission ep)
        {
            if (_entityPermissions.Any(e => e.ActionCategory == ep.ActionCategory && e.ActionName == ep.ActionName && e.Id == ep.Id))
                throw new InvalidOperationException("Duplicate EntityPermission.");
            _entityPermissions.Add(ep);
        }

        public void Update(EntityPermission entityPermission)
        {
            var permission =
                _entityPermissions.SingleOrDefault(ep => ep.Id == entityPermission.Id);
            if (permission != null)
            {
                permission.EntityId = entityPermission.EntityId;
                permission.ActionName = entityPermission.ActionName;
                permission.ActionCategory = entityPermission.ActionCategory;
                permission.RoleName = entityPermission.RoleName;
                permission.Permission = entityPermission.Permission;
            }
            else
            {
                throw new Exception("Entity Permision With this id not found");
            }
        }
    }
}