using System;
using System.Collections.Generic;

namespace TAuthorization
{
    public class EntityPermission
    {
        private Dictionary<string, string> _rawActionParams = new Dictionary<string, string>();

        public virtual Guid Id { get; set; }
        public virtual string EntityId { get; set; }
        public virtual string Action { get; set; }
        public virtual string ActionTitle { get; set; }
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

    public class EntityServicePermission
    {
        private Dictionary<string, string> _rawActionParams = new Dictionary<string, string>();

        public virtual Guid Id { get; set; }
        public virtual string Action { get; set; }
        public virtual string UserId { get; set; }
        public virtual Permission Permission { get; set; }

        public virtual Dictionary<string, string> RawActionParams
        {
            get { return _rawActionParams; }
            set { _rawActionParams = value; }
        }
    }

}
