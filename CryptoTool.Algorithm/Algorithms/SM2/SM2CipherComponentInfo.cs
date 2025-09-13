namespace CryptoTool.Algorithm.Algorithms.SM2
{
    /// <summary>
    /// 密文组件信息
    /// </summary>
    public class SM2CipherComponentInfo
    {
        /// <summary>
        /// 密文格式
        /// </summary>
        public SM2CipherFormat Format { get; set; }

        /// <summary>
        /// C1组件长度
        /// </summary>
        public int C1Length { get; set; }

        /// <summary>
        /// C2组件长度
        /// </summary>
        public int C2Length { get; set; }

        /// <summary>
        /// C3组件长度
        /// </summary>
        public int C3Length { get; set; }

        /// <summary>
        /// 总长度
        /// </summary>
        public int TotalLength { get; set; }

        /// <summary>
        /// 获取格式字符串
        /// </summary>
        public string FormatString => Sm2CipherFormatConverter.GetFormatString(Format);

        /// <summary>
        /// 转换为字符串表示
        /// </summary>
        public override string ToString()
        {
            return $"格式: {FormatString}, C1: {C1Length}字节, C2: {C2Length}字节, C3: {C3Length}字节, 总计: {TotalLength}字节";
        }
    }
}
