﻿using Microsoft.AspNetCore.Authorization;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthorizationPolicyProvider.Policy
{
    public class MinimumTimeSpendRequirement: IAuthorizationRequirement
    {
        public MinimumTimeSpendRequirement(int noOfDays)
        {
            TimeSpendInDays = noOfDays;
        }

        public int TimeSpendInDays { get; private set; }
    }
}
