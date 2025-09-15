using CryptoTool.Algorithm.Exceptions;
using System;

namespace CryptoTool.Algorithm.Algorithms.SM2
{
    /// <summary>
    /// SM2密文格式转换器
    /// 支持C1C2C3和C1C3C2两种密文格式的互转
    /// </summary>
    public static class Sm2CipherFormatConverter
    {
        /// <summary>
        /// SM2密文组件长度常量
        /// </summary>
        private const int C1_LENGTH = 65; // C1（椭圆曲线点）长度：1字节标识 + 32字节X + 32字节Y
        private const int C2_LENGTH_OFFSET = 0; // C2长度偏移（动态长度）
        private const int C3_LENGTH = 32; // C3（哈希值）长度：32字节

        /// <summary>
        /// 将C1C2C3格式转换为C1C3C2格式
        /// </summary>
        /// <param name="c1c2c3Data">C1C2C3格式的密文数据</param>
        /// <returns>C1C3C2格式的密文数据</returns>
        public static byte[] C1C2C3ToC1C3C2(byte[] c1c2c3Data)
        {
            if (c1c2c3Data == null || c1c2c3Data.Length == 0)
                throw new DataException("C1C2C3密文数据不能为空");

            if (c1c2c3Data.Length < C1_LENGTH + C3_LENGTH)
                throw new DataException("C1C2C3密文数据长度不足");

            try
            {
                // 解析C1C2C3格式
                var (c1, c2, c3) = ParseC1C2C3(c1c2c3Data);

                // 重新组装为C1C3C2格式
                return AssembleC1C3C2(c1, c2, c3);
            }
            catch (Exception ex)
            {
                throw new CryptoException("C1C2C3转C1C3C2失败", ex);
            }
        }

        /// <summary>
        /// 将C1C3C2格式转换为C1C2C3格式
        /// </summary>
        /// <param name="c1c3c2Data">C1C3C2格式的密文数据</param>
        /// <returns>C1C2C3格式的密文数据</returns>
        public static byte[] C1C3C2ToC1C2C3(byte[] c1c3c2Data)
        {
            if (c1c3c2Data == null || c1c3c2Data.Length == 0)
                throw new DataException("C1C3C2密文数据不能为空");

            if (c1c3c2Data.Length < C1_LENGTH + C3_LENGTH)
                throw new DataException("C1C3C2密文数据长度不足");

            try
            {
                // 解析C1C3C2格式
                var (c1, c2, c3) = ParseC1C3C2(c1c3c2Data);

                // 重新组装为C1C2C3格式
                return AssembleC1C2C3(c1, c2, c3);
            }
            catch (Exception ex)
            {
                throw new CryptoException("C1C3C2转C1C2C3失败", ex);
            }
        }

        /// <summary>
        /// 检测密文格式
        /// </summary>
        /// <param name="cipherData">密文数据</param>
        /// <returns>密文格式</returns>
        public static SM2CipherFormat DetectFormat(byte[] cipherData)
        {
            if (cipherData == null || cipherData.Length == 0)
                throw new DataException("密文数据不能为空");

            if (cipherData.Length < C1_LENGTH + C3_LENGTH)
                throw new DataException("密文数据长度不足");

            try
            {
                // 尝试解析为C1C2C3格式
                var (c1, c2, c3) = ParseC1C2C3(cipherData);

                // 验证C1格式（椭圆曲线点）
                if (IsValidC1(c1))
                {
                    return SM2CipherFormat.C1C2C3;
                }
            }
            catch
            {
                // 解析失败，尝试C1C3C2格式
            }

            try
            {
                // 尝试解析为C1C3C2格式
                var (c1, c2, c3) = ParseC1C3C2(cipherData);

                // 验证C1格式（椭圆曲线点）
                if (IsValidC1(c1))
                {
                    return SM2CipherFormat.C1C3C2;
                }
            }
            catch
            {
                // 解析失败
            }

            throw new CryptoException("无法识别密文格式");
        }

        /// <summary>
        /// 解析C1C2C3格式密文
        /// </summary>
        /// <param name="c1c2c3Data">C1C2C3格式密文</param>
        /// <returns>C1、C2、C3组件</returns>
        private static (byte[] C1, byte[] C2, byte[] C3) ParseC1C2C3(byte[] c1c2c3Data)
        {
            // C1: 前65字节
            var c1 = new byte[C1_LENGTH];
            Array.Copy(c1c2c3Data, 0, c1, 0, C1_LENGTH);

            // C3: 最后32字节
            var c3 = new byte[C3_LENGTH];
            Array.Copy(c1c2c3Data, c1c2c3Data.Length - C3_LENGTH, c3, 0, C3_LENGTH);

            // C2: 中间部分
            var c2Length = c1c2c3Data.Length - C1_LENGTH - C3_LENGTH;
            var c2 = new byte[c2Length];
            Array.Copy(c1c2c3Data, C1_LENGTH, c2, 0, c2Length);

            return (c1, c2, c3);
        }

        /// <summary>
        /// 解析C1C3C2格式密文
        /// </summary>
        /// <param name="c1c3c2Data">C1C3C2格式密文</param>
        /// <returns>C1、C2、C3组件</returns>
        private static (byte[] C1, byte[] C2, byte[] C3) ParseC1C3C2(byte[] c1c3c2Data)
        {
            // C1: 前65字节
            var c1 = new byte[C1_LENGTH];
            Array.Copy(c1c3c2Data, 0, c1, 0, C1_LENGTH);

            // C3: 中间32字节
            var c3 = new byte[C3_LENGTH];
            Array.Copy(c1c3c2Data, C1_LENGTH, c3, 0, C3_LENGTH);

            // C2: 最后部分
            var c2Length = c1c3c2Data.Length - C1_LENGTH - C3_LENGTH;
            var c2 = new byte[c2Length];
            Array.Copy(c1c3c2Data, C1_LENGTH + C3_LENGTH, c2, 0, c2Length);

            return (c1, c2, c3);
        }

        /// <summary>
        /// 组装C1C2C3格式密文
        /// </summary>
        /// <param name="c1">C1组件</param>
        /// <param name="c2">C2组件</param>
        /// <param name="c3">C3组件</param>
        /// <returns>C1C2C3格式密文</returns>
        private static byte[] AssembleC1C2C3(byte[] c1, byte[] c2, byte[] c3)
        {
            if (c1 == null || c1.Length != C1_LENGTH)
                throw new DataException("C1组件长度不正确");

            if (c3 == null || c3.Length != C3_LENGTH)
                throw new DataException("C3组件长度不正确");

            var result = new byte[c1.Length + c2.Length + c3.Length];
            var offset = 0;

            // C1
            Array.Copy(c1, 0, result, offset, c1.Length);
            offset += c1.Length;

            // C2
            Array.Copy(c2, 0, result, offset, c2.Length);
            offset += c2.Length;

            // C3
            Array.Copy(c3, 0, result, offset, c3.Length);

            return result;
        }

        /// <summary>
        /// 组装C1C3C2格式密文
        /// </summary>
        /// <param name="c1">C1组件</param>
        /// <param name="c2">C2组件</param>
        /// <param name="c3">C3组件</param>
        /// <returns>C1C3C2格式密文</returns>
        private static byte[] AssembleC1C3C2(byte[] c1, byte[] c2, byte[] c3)
        {
            if (c1 == null || c1.Length != C1_LENGTH)
                throw new DataException("C1组件长度不正确");

            if (c3 == null || c3.Length != C3_LENGTH)
                throw new DataException("C3组件长度不正确");

            var result = new byte[c1.Length + c2.Length + c3.Length];
            var offset = 0;

            // C1
            Array.Copy(c1, 0, result, offset, c1.Length);
            offset += c1.Length;

            // C3
            Array.Copy(c3, 0, result, offset, c3.Length);
            offset += c3.Length;

            // C2
            Array.Copy(c2, 0, result, offset, c2.Length);

            return result;
        }

        /// <summary>
        /// 验证C1组件格式
        /// </summary>
        /// <param name="c1">C1组件</param>
        /// <returns>是否有效</returns>
        private static bool IsValidC1(byte[] c1)
        {
            if (c1 == null || c1.Length != C1_LENGTH)
                return false;

            // 检查第一个字节是否为有效的椭圆曲线点标识
            // 0x04表示未压缩点格式
            return c1[0] == 0x04;
        }

        /// <summary>
        /// 获取密文格式的字符串表示
        /// </summary>
        /// <param name="format">密文格式</param>
        /// <returns>格式字符串</returns>
        public static string GetFormatString(SM2CipherFormat format)
        {
            return format switch
            {
                SM2CipherFormat.C1C2C3 => "C1C2C3",
                SM2CipherFormat.C1C3C2 => "C1C3C2",
                _ => "Unknown"
            };
        }

        /// <summary>
        /// 验证密文数据完整性
        /// </summary>
        /// <param name="cipherData">密文数据</param>
        /// <param name="expectedFormat">期望的格式</param>
        /// <returns>是否有效</returns>
        public static bool ValidateCipherData(byte[] cipherData, SM2CipherFormat expectedFormat)
        {
            if (cipherData == null || cipherData.Length == 0)
                return false;

            try
            {
                var detectedFormat = DetectFormat(cipherData);
                return detectedFormat == expectedFormat;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// 获取密文组件信息
        /// </summary>
        /// <param name="cipherData">密文数据</param>
        /// <returns>组件信息</returns>
        public static SM2CipherComponentInfo GetComponentInfo(byte[] cipherData)
        {
            if (cipherData == null || cipherData.Length == 0)
                throw new DataException("密文数据不能为空");

            var format = DetectFormat(cipherData);

            return format switch
            {
                SM2CipherFormat.C1C2C3 => GetC1C2C3ComponentInfo(cipherData),
                SM2CipherFormat.C1C3C2 => GetC1C3C2ComponentInfo(cipherData),
                _ => throw new CryptoException("不支持的密文格式")
            };
        }

        /// <summary>
        /// 获取C1C2C3格式组件信息
        /// </summary>
        private static SM2CipherComponentInfo GetC1C2C3ComponentInfo(byte[] cipherData)
        {
            var (c1, c2, c3) = ParseC1C2C3(cipherData);
            return new SM2CipherComponentInfo
            {
                Format = SM2CipherFormat.C1C2C3,
                C1Length = c1.Length,
                C2Length = c2.Length,
                C3Length = c3.Length,
                TotalLength = cipherData.Length
            };
        }

        /// <summary>
        /// 获取C1C3C2格式组件信息
        /// </summary>
        private static SM2CipherComponentInfo GetC1C3C2ComponentInfo(byte[] cipherData)
        {
            var (c1, c2, c3) = ParseC1C3C2(cipherData);
            return new SM2CipherComponentInfo
            {
                Format = SM2CipherFormat.C1C3C2,
                C1Length = c1.Length,
                C2Length = c2.Length,
                C3Length = c3.Length,
                TotalLength = cipherData.Length
            };
        }
    }

}
