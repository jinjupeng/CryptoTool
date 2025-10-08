using CryptoTool.Algorithm.Factory;
using CryptoTool.Test.Examples;
using System;
using System.Text;
using System.Threading.Tasks;

namespace CryptoTool.Test
{
    class Program
    {
        static void Main(string[] args)
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
                AESTest.RunTest();

                // 运行DES测试
                DESTest.RunTest();

                // 运行RSA测试
                RSATest.RunTest();

                // 运行SM2测试
                SM2Test.RunTest();

                // 运行SM3测试
                SM3Test.RunTest();

                // 运行SM4测试
                SM4Test.RunTest();

                // 运行MD5测试
                MD5Test.RunTest();

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
