using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using System.Threading.Tasks;
using CryptoTool.Algorithm;
using CryptoTool.Algorithm.Factory;
using CryptoTool.Algorithm.Utils;
using CryptoTool.Algorithm.Interfaces;
using CryptoTool.Algorithm.Algorithms.SM2;
using CryptoTool.Test.Examples;
using System.Linq;

namespace CryptoTool.Test
{
    class Program
    {
        static async Task Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;
            Console.WriteLine("=== 加密算法类库完整测试 ===");
            Console.WriteLine("支持算法: RSA、DES、AES、SM2、SM3、SM4、MD5");
            Console.WriteLine();
            // TODO：将Examples文件下的测试类统一在这里调用，实现都在各自的类中实现

        }
    }
}
