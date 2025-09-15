using CryptoTool.Algorithm.Factory;
using System;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoTool.Test.Examples
{
    public class SM3Test
    {
        /// <summary>
        /// 运行SM3算法测试
        /// </summary>
        public static async Task RunTest()
        {
            Console.WriteLine("=== SM3算法测试 ===");

            try
            {
                // 创建SM3算法实例
                var sm3 = CryptoFactory.CreateSm3();
                Console.WriteLine($"算法名称: {sm3.AlgorithmName}");
                Console.WriteLine($"算法类型: {sm3.AlgorithmType}");
                Console.WriteLine($"哈希长度: {sm3.HashLength} 字节");

                // 测试数据
                string testData = "这是一个SM3哈希测试数据，包含中文字符和特殊符号!@#$%^&*()";
                byte[] data = Encoding.UTF8.GetBytes(testData);
                Console.WriteLine($"原始数据: {testData}");
                Console.WriteLine($"数据长度: {data.Length} 字节");

                // 计算哈希值
                Console.WriteLine("\n--- 哈希计算测试 ---");
                byte[] hash = sm3.ComputeHash(data);
                Console.WriteLine($"哈希计算成功，哈希长度: {hash.Length} 字节");
                Console.WriteLine($"哈希值(Hex): {BitConverter.ToString(hash).Replace("-", "")}");

                // 验证哈希一致性
                Console.WriteLine("\n--- 哈希一致性测试 ---");
                byte[] hash2 = sm3.ComputeHash(data);
                bool isConsistent = hash.SequenceEqual(hash2);
                Console.WriteLine($"哈希一致性测试: {(isConsistent ? "通过" : "失败")}");

                // 异步测试
                Console.WriteLine("\n--- 异步哈希计算测试 ---");
                byte[] asyncHash = await sm3.ComputeHashAsync(data);
                bool asyncConsistent = hash.SequenceEqual(asyncHash);
                Console.WriteLine($"异步哈希计算测试: {(asyncConsistent ? "通过" : "失败")}");

                // 不同数据测试
                Console.WriteLine("\n--- 不同数据哈希测试 ---");
                TestDifferentData();

                // 大数据测试
                Console.WriteLine("\n--- 大数据哈希测试 ---");
                TestLargeData();

                // 空数据测试
                Console.WriteLine("\n--- 空数据哈希测试 ---");
                TestEmptyData();

                // 性能测试
                Console.WriteLine("\n--- 性能测试 ---");
                TestPerformance();

            }
            catch (Exception ex)
            {
                Console.WriteLine($"SM3测试失败: {ex.Message}");
                Console.WriteLine($"异常详情: {ex}");
            }

            Console.WriteLine("=== SM3算法测试完成 ===\n");
        }

        /// <summary>
        /// 测试不同数据的哈希
        /// </summary>
        private static void TestDifferentData()
        {
            var sm3 = CryptoFactory.CreateSm3();

            string[] testDataArray = {
                "Hello World",
                "你好世界",
                "1234567890",
                "!@#$%^&*()",
                "a",
                "ab",
                "abc",
                "abcd",
                "abcde"
            };

            foreach (string testData in testDataArray)
            {
                byte[] data = Encoding.UTF8.GetBytes(testData);
                byte[] hash = sm3.ComputeHash(data);
                Console.WriteLine($"数据: \"{testData}\" -> 哈希: {BitConverter.ToString(hash).Replace("-", "")}");
            }
        }

        /// <summary>
        /// 测试大数据
        /// </summary>
        private static void TestLargeData()
        {
            var sm3 = CryptoFactory.CreateSm3();

            // 生成1MB的测试数据
            string largeData = new string('A', 1024 * 1024);
            byte[] data = Encoding.UTF8.GetBytes(largeData);

            try
            {
                var stopwatch = System.Diagnostics.Stopwatch.StartNew();
                byte[] hash = sm3.ComputeHash(data);
                stopwatch.Stop();

                Console.WriteLine($"大数据测试(1MB): 通过");
                Console.WriteLine($"哈希值: {BitConverter.ToString(hash).Replace("-", "")}");
                Console.WriteLine($"计算时间: {stopwatch.ElapsedMilliseconds} 毫秒");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"大数据测试失败: {ex.Message}");
            }
        }

        /// <summary>
        /// 测试空数据
        /// </summary>
        private static void TestEmptyData()
        {
            var sm3 = CryptoFactory.CreateSm3();

            try
            {
                byte[] emptyData = new byte[0];
                byte[] hash = sm3.ComputeHash(emptyData);
                Console.WriteLine($"空数据哈希测试: 通过");
                Console.WriteLine($"空数据哈希值: {BitConverter.ToString(hash).Replace("-", "")}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"空数据测试失败: {ex.Message}");
            }
        }

        /// <summary>
        /// 性能测试
        /// </summary>
        private static void TestPerformance()
        {
            var sm3 = CryptoFactory.CreateSm3();
            string testData = "SM3性能测试数据";
            byte[] data = Encoding.UTF8.GetBytes(testData);

            int iterations = 10000;
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();

            for (int i = 0; i < iterations; i++)
            {
                sm3.ComputeHash(data);
            }

            stopwatch.Stop();

            double avgTime = (double)stopwatch.ElapsedMilliseconds / iterations;
            Console.WriteLine($"性能测试({iterations}次): 通过");
            Console.WriteLine($"总时间: {stopwatch.ElapsedMilliseconds} 毫秒");
            Console.WriteLine($"平均时间: {avgTime:F4} 毫秒/次");
        }
    }
}
