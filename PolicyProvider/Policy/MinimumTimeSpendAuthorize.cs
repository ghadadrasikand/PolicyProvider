﻿using Microsoft.AspNetCore.Authorization;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthorizationPolicyProvider.Policy
{
    public class MinimumTimeSpendAuthorize:AuthorizeAttribute
    {
        public MinimumTimeSpendAuthorize(int days)
        {
            NoOfDays = days;
        }

        int days;

        public int NoOfDays
        {
            get
            {
                return days;
            }
            set
            {
                days = value;
                Policy = $"{"MinimumTimeSpend"}.{value.ToString()}";
            }
        }
    }
}
