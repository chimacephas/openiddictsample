using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OpenIddictSample.Models
{
    public class OpenIddictServerConfig
    {
        public string SecretKey { get; set; }
        public string Authority { get; set; }
        public bool RequireHttps { get; set; }
    }
}
