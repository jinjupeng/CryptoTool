using System;

namespace CryptoTool.Algorithm.Exceptions
{
    /// <summary>
    /// 加密算法异常基类
    /// </summary>
    public class CryptoException : Exception
    {
        public CryptoException(string message) : base(message)
        {
        }

        public CryptoException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }

    /// <summary>
    /// 密钥异常
    /// </summary>
    public class KeyException : CryptoException
    {
        public KeyException(string message) : base(message)
        {
        }

        public KeyException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }

    /// <summary>
    /// 数据异常
    /// </summary>
    public class DataException : CryptoException
    {
        public DataException(string message) : base(message)
        {
        }

        public DataException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }

    /// <summary>
    /// 算法不支持异常
    /// </summary>
    public class AlgorithmNotSupportedException : CryptoException
    {
        public AlgorithmNotSupportedException(string message) : base(message)
        {
        }

        public AlgorithmNotSupportedException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}
