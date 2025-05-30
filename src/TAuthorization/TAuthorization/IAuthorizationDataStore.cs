﻿using System.Collections.Generic;
using System.Linq;

namespace TAuthorization
{
    public interface IAuthorizationDataStore
    {
        IQueryable<EntityPermission> Query();
        void Delete(List<EntityPermission> entityPermissions);
        void Insert(EntityPermission ep);
        void Update(EntityPermission entityPermission);
    }

    public interface IServiceAuthorizationDataStore
    {
        IQueryable<EntityServicePermission> Query();
        void Delete(List<EntityServicePermission> entityPermissions);
        void Insert(EntityServicePermission ep);
        void Update(EntityServicePermission entityPermission);
    }
}