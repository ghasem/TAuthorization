using System.Collections.Generic;
using System.Linq;

namespace TAuthorization
{
    public interface IAuthorizationDataStore
    {
        IQueryable<EntityPermission> Query();
        void Delete(List<EntityPermission> entityPermissions);
        EntityPermission Insert(EntityPermission ep);
        EntityPermission Update(EntityPermission entityPermission);
    }
}