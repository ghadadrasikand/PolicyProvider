using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Threading.Tasks;

namespace AuthorizationPolicyProvider
{
    public class CustomAuthenticationManager : ICustomAuthenticationManager
    {
        //DateTime startdate;

        private readonly IDictionary<string, string> users = new Dictionary<string, string>
        {
            {"test1","password1"},
            {"test2","password2"}

        };
        private readonly IDictionary<string, string> tokens = new Dictionary<string, string>();
        public IDictionary<string, string> Tokens => tokens;
        public string Authenticate(string username, string password)
        {
            if (!users.Any(u => u.Key == username && u.Value == password))
            {
                return null;
            }
            string token = "2017-02-21";

            tokens.Add(token, username);
            return token;
        }

       
    }
}
