using System;
using CryptoTool.Test.Examples;

namespace CryptoTool.Test
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("=== SM4国密对称加密算法测试 ===");
            Console.WriteLine();

            try
            {
                // 运行SM4示例
                Sm4CryptoExample.RunAllExamples().Wait();
                
                Console.WriteLine("SM4测试完成！");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"测试失败: {ex.Message}");
                Console.WriteLine($"详细错误: {ex}");
            }

            Console.WriteLine();
            Console.WriteLine("按任意键退出...");
            Console.ReadKey();
        }
    }
}
