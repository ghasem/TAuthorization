using System;
using System.Collections.Generic;

namespace TAuthorization
{
    public class EntityPermission
    {
        private Dictionary<string, string> _rawActionParams = new Dictionary<string, string>();

        public virtual Guid Id { get; set; }
        public virtual Guid EntityId { get; set; }
        public virtual string ActionName { get; set; }
        public virtual string ActionCategory { get; set; }
        public virtual string RoleName { get; set; }
        public virtual Permission Permission { get; set; }

        public virtual Dictionary<string, string> RawActionParams
        {
            get { return _rawActionParams; }
            set { _rawActionParams = value; }
        }
    }

    public class EntityPermission<TActionParamsType> : EntityPermission
    {
        public TActionParamsType ActionParameters { get; set; }
    }
}
