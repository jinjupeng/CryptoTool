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
            
            try
            {
                // 显示支持的算法列表
                Console.WriteLine("--- 支持的算法列表 ---");
                var supportedAlgorithms = CryptoFactory.GetSupportedAlgorithms();
                foreach (var algorithm in supportedAlgorithms)
                {
                    var algorithmType = CryptoFactory.GetAlgorithmType(algorithm);
                    Console.WriteLine($"- {algorithm}: {algorithmType}");
                }
                Console.WriteLine();
                
                // 运行所有算法测试
                Console.WriteLine("开始运行所有算法测试...\n");
                
                // 运行AES测试
                await AESTest.RunTest();
                
                // 运行DES测试
                await DESTest.RunTest();
                
                // 运行RSA测试
                await RSATest.RunTest();
                
                // 运行SM2测试
                await SM2Test.RunTest();
                
                // 运行SM3测试
                await SM3Test.RunTest();
                
                // 运行SM4测试
                await SM4Test.RunTest();
                
                // 运行MD5测试
                await MD5Test.RunTest();
                
                Console.WriteLine("=== 所有算法测试完成 ===");
                Console.WriteLine("按任意键退出...");
                Console.ReadKey();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"测试过程中发生错误: {ex.Message}");
                Console.WriteLine($"异常详情: {ex}");
                Console.WriteLine("按任意键退出...");
                Console.ReadKey();
            }
        }
    }
}
