using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using CryptoTool.Algorithm.Factory;
using CryptoTool.Algorithm.Interfaces;

namespace CryptoTool.Test.Examples
{
    internal class MD5Test
    {
        /// <summary>
        /// 运行MD5算法测试
        /// </summary>
        public static async Task RunTest()
        {
            Console.WriteLine("=== MD5算法测试 ===");
            
            try
            {
                // 创建MD5算法实例
                var md5 = CryptoFactory.CreateMd5();
                Console.WriteLine($"算法名称: {md5.AlgorithmName}");
                Console.WriteLine($"算法类型: {md5.AlgorithmType}");
                Console.WriteLine($"哈希长度: {md5.HashLength} 字节");
                
                // 测试数据
                string testData = "这是一个MD5哈希测试数据，包含中文字符和特殊符号!@#$%^&*()";
                byte[] data = Encoding.UTF8.GetBytes(testData);
                Console.WriteLine($"原始数据: {testData}");
                Console.WriteLine($"数据长度: {data.Length} 字节");
                
                // 计算哈希值
                Console.WriteLine("\n--- 哈希计算测试 ---");
                byte[] hash = md5.ComputeHash(data);
                Console.WriteLine($"哈希计算成功，哈希长度: {hash.Length} 字节");
                Console.WriteLine($"哈希值(Hex): {BitConverter.ToString(hash).Replace("-", "")}");
                
                // 验证哈希一致性
                Console.WriteLine("\n--- 哈希一致性测试 ---");
                byte[] hash2 = md5.ComputeHash(data);
                bool isConsistent = hash.SequenceEqual(hash2);
                Console.WriteLine($"哈希一致性测试: {(isConsistent ? "通过" : "失败")}");
                
                // 异步测试
                Console.WriteLine("\n--- 异步哈希计算测试 ---");
                byte[] asyncHash = await md5.ComputeHashAsync(data);
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
                Console.WriteLine($"MD5测试失败: {ex.Message}");
                Console.WriteLine($"异常详情: {ex}");
            }
            
            Console.WriteLine("=== MD5算法测试完成 ===\n");
        }
        
        /// <summary>
        /// 测试不同数据的哈希
        /// </summary>
        private static void TestDifferentData()
        {
            var md5 = CryptoFactory.CreateMd5();
            
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
                byte[] hash = md5.ComputeHash(data);
                Console.WriteLine($"数据: \"{testData}\" -> 哈希: {BitConverter.ToString(hash).Replace("-", "")}");
            }
        }
        
        /// <summary>
        /// 测试大数据
        /// </summary>
        private static void TestLargeData()
        {
            var md5 = CryptoFactory.CreateMd5();
            
            // 生成1MB的测试数据
            string largeData = new string('A', 1024 * 1024);
            byte[] data = Encoding.UTF8.GetBytes(largeData);
            
            try
            {
                var stopwatch = System.Diagnostics.Stopwatch.StartNew();
                byte[] hash = md5.ComputeHash(data);
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
            var md5 = CryptoFactory.CreateMd5();
            
            try
            {
                byte[] emptyData = new byte[0];
                byte[] hash = md5.ComputeHash(emptyData);
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
            var md5 = CryptoFactory.CreateMd5();
            string testData = "MD5性能测试数据";
            byte[] data = Encoding.UTF8.GetBytes(testData);
            
            int iterations = 10000;
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            
            for (int i = 0; i < iterations; i++)
            {
                md5.ComputeHash(data);
            }
            
            stopwatch.Stop();
            
            double avgTime = (double)stopwatch.ElapsedMilliseconds / iterations;
            Console.WriteLine($"性能测试({iterations}次): 通过");
            Console.WriteLine($"总时间: {stopwatch.ElapsedMilliseconds} 毫秒");
            Console.WriteLine($"平均时间: {avgTime:F4} 毫秒/次");
        }
    }
}
