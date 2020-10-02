using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace ElevateHandle
{
    unsafe class Program
    {
        static void Main(string[] args)
        {
            Handle.Driver.Load();
            Handle.UpdateDynamicData();
            Handle.Elevate(0xDEADBEEF, 0xDEADBEEF);
            Handle.Driver.Unload();
        }
    }
}
