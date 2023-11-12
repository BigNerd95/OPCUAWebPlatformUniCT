using System;
namespace WebPlatform.Models.OptionsModels
{
    public class OPCUAServersOptions
    {
        public OPCUAServersOptions() {}

        public OPCUAServers[] Servers { get; set; }
    }

    public class OPCUAServers {

        public OPCUAServers() {}

        public int Id { get; set; }
        public string Name { get; set; }
        public string Url { get; set; }

        [Newtonsoft.Json.JsonIgnore]
        public bool Auth { get; set; }

        [Newtonsoft.Json.JsonIgnore]
        public string User { get; set; }

        [Newtonsoft.Json.JsonIgnore]
        public string Password { get; set; }
    }


 
}
