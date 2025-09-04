using CryptoTool.Common.GM;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace CryptoTool.Common
{
    /// <summary>
    /// 医保工具：按规范实现请求签名/验签与报文加解密（SM2/SM4）
    /// </summary>
    public class MedicareUtil
    {
        private static readonly string[] ExcludeKeys = new[] { "signData", "encData", "extra" };

        #region 对外主功能

        /// <summary>
        /// 构造待签名原文（筛选->排序->拼接后追加 &key=appSecret）
        /// </summary>
        public static string BuildSignatureBaseString(IDictionary<string, object> parameters, string appSecret)
        {
            if (parameters == null) throw new ArgumentNullException(nameof(parameters));
            if (string.IsNullOrEmpty(appSecret)) throw new ArgumentNullException(nameof(appSecret));

            // 1) 筛选：剔除 signData/encData/extra，忽略空值
            var filtered = parameters
                .Where(kv => !IsExcludedKey(kv.Key) && !IsNullOrEmptyValue(kv.Value))
                .ToDictionary(kv => kv.Key, kv => kv.Value);

            // 2) 排序：ASCII 升序
            var orderedKeys = filtered.Keys.OrderBy(k => k, StringComparer.Ordinal).ToArray();

            // 3) 拼接：key=value 用 & 连接；对象型按JSON内部字母序升序，空值不参与
            var parts = new List<string>(orderedKeys.Length);
            foreach (var key in orderedKeys)
            {
                string valueStr = SerializeValue(filtered[key]);
                parts.Add($"{key}={valueStr}");
            }

            string baseString = string.Join("&", parts) + $"&key={appSecret}";
            return baseString;
        }

        /// <summary>
        /// 使用SM2签名请求参数，返回Base64签名串（signData）
        /// </summary>
        public static string SignParameters(IDictionary<string, object> parameters, ECPrivateKeyParameters privateKey, string appSecret)
        {
            if (privateKey == null) throw new ArgumentNullException(nameof(privateKey));
            string baseString = BuildSignatureBaseString(parameters, appSecret);

            // 使用SM2+SM3签名，默认ASN.1，工具返回Hex，需要转Base64
            string hexAsn1 = SM2Util.SignSm3WithSm2(Encoding.UTF8.GetBytes(baseString), privateKey);
            byte[] sigBytes = Hex.Decode(hexAsn1);
            return Convert.ToBase64String(sigBytes);
        }

        /// <summary>
        /// 验证返回参数SM2签名（signData为Base64）
        /// </summary>
        public static bool VerifyParametersSignature(IDictionary<string, object> parameters, string signDataBase64, ECPublicKeyParameters publicKey, string appSecret)
        {
            if (publicKey == null) throw new ArgumentNullException(nameof(publicKey));
            if (string.IsNullOrEmpty(signDataBase64)) throw new ArgumentNullException(nameof(signDataBase64));

            string baseString = BuildSignatureBaseString(parameters, appSecret);
            byte[] sigBytes = Convert.FromBase64String(signDataBase64.Trim());
            string hexAsn1 = Org.BouncyCastle.Utilities.Encoders.Hex.ToHexString(sigBytes).ToUpperInvariant();
            return SM2Util.VerifySm3WithSm2(Encoding.UTF8.GetBytes(baseString), hexAsn1, publicKey);
        }

        /// <summary>
        /// 根据规范派生SM4密钥，并对data(JSON)进行加密，输出Hex大写的encData。
        /// 规则：newKeyStr = SM4_ECB_Enc(appSecret, key=appId)，取newKeyStr去掉'='后的前32位，再取前16位作为SM4最终密钥，对jStr进行加密；输出Hex大写。
        /// </summary>
        public static string EncryptData(object dataObject, string appId, string appSecret)
        {
            if (dataObject == null) throw new ArgumentNullException(nameof(dataObject));
            if (string.IsNullOrEmpty(appId)) throw new ArgumentNullException(nameof(appId));
            if (string.IsNullOrEmpty(appSecret)) throw new ArgumentNullException(nameof(appSecret));

            // 1) 生成data的规范化JSON字符串
            string jStr = SerializeObjectCanonicalJson(dataObject);

            // 2) 派生SM4密钥
            string derived16 = DeriveSm4Key16(appId, appSecret);

            // 3) 使用派生密钥加密jStr，得到Base64，再转Hex大写
            string base64 = SM4Util.EncryptEcb(jStr, derived16);
            byte[] cipherBytes = Convert.FromBase64String(base64);
            string encHex = SM4Util.BytesToHex(cipherBytes);
            return encHex;
        }

        /// <summary>
        /// 解密响应中的encData(Hex)，返回明文JSON字符串jStr。
        /// </summary>
        public static string DecryptEncData(string encDataHex, string appId, string appSecret)
        {
            if (string.IsNullOrEmpty(encDataHex)) throw new ArgumentNullException(nameof(encDataHex));
            if (string.IsNullOrEmpty(appId)) throw new ArgumentNullException(nameof(appId));
            if (string.IsNullOrEmpty(appSecret)) throw new ArgumentNullException(nameof(appSecret));

            string derived16 = DeriveSm4Key16(appId, appSecret);
            byte[] cipherBytes = SM4Util.HexToBytes(encDataHex);
            string base64 = Convert.ToBase64String(cipherBytes);
            string jStr = SM4Util.DecryptEcb(base64, derived16);
            return jStr;
        }

        /// <summary>
        /// 将请求中的data对象加密为encData(Hex大写)，并清空/移除data字段。
        /// </summary>
        public static void ApplyRequestEncryption(IDictionary<string, object> request, string appId, string appSecret)
        {
            if (request == null) throw new ArgumentNullException(nameof(request));

            if (request.TryGetValue("data", out var dataObj) && dataObj != null)
            {
                string encHex = EncryptData(dataObj, appId, appSecret);
                request["encData"] = encHex;
                // 清空data
                request.Remove("data");
            }
        }

        /// <summary>
        /// 解密响应中的encData，并把解析结果设置到data字段；保留原encData。
        /// </summary>
        public static void DecryptResponseToData(IDictionary<string, object> response, string appId, string appSecret)
        {
            if (response == null) throw new ArgumentNullException(nameof(response));
            if (!response.TryGetValue("encData", out var encObj) || encObj == null) return;

            string encHex = encObj.ToString();
            string jStr = DecryptEncData(encHex, appId, appSecret);
            var dataToken = JToken.Parse(jStr);
            response["data"] = dataToken;
        }

        #endregion

        #region 辅助 - 规范化JSON与值序列化

        private static bool IsExcludedKey(string key)
        {
            return ExcludeKeys.Any(k => string.Equals(k, key, StringComparison.OrdinalIgnoreCase));
        }

        private static bool IsNullOrEmptyValue(object value)
        {
            if (value == null) return true;
            if (value is string s) return string.IsNullOrEmpty(s);
            if (value is JValue jv) return jv.Type == JTokenType.Null || (jv.Type == JTokenType.String && string.IsNullOrEmpty(jv.Value?.ToString()));
            return false;
        }

        private static string SerializeValue(object value)
        {
            if (value == null) return string.Empty;

            // 对象或数组 -> 规范化JSON
            if (value is JToken jt)
            {
                return SerializeTokenCanonical(jt);
            }

            // 尝试把任意对象转换为JToken并规范化
            if (!(value is string) && !IsSimple(value))
            {
                var token = JToken.FromObject(value);
                return SerializeTokenCanonical(token);
            }

            // 字符串/简单类型直接ToString
            return value.ToString();
        }

        private static bool IsSimple(object value)
        {
            var t = value.GetType();
            return t.IsPrimitive || t.IsEnum || t == typeof(string) || t == typeof(decimal) || t == typeof(DateTime) || t == typeof(Guid);
        }

        private static string SerializeObjectCanonicalJson(object obj)
        {
            if (obj is JToken token)
            {
                return SerializeTokenCanonical(token);
            }
            var t = JToken.FromObject(obj);
            return SerializeTokenCanonical(t);
        }

        private static string SerializeTokenCanonical(JToken token)
        {
            var canonical = ToCanonical(token);
            return JsonConvert.SerializeObject(canonical, Formatting.None, new JsonSerializerSettings
            {
                NullValueHandling = NullValueHandling.Ignore,
                StringEscapeHandling = StringEscapeHandling.Default
            });
        }

        private static JToken ToCanonical(JToken token)
        {
            switch (token.Type)
            {
                case JTokenType.Object:
                    var obj = (JObject)token;
                    var props = obj.Properties()
                        .Where(p => p.Value.Type != JTokenType.Null)
                        .OrderBy(p => p.Name, StringComparer.Ordinal)
                        .Select(p => new JProperty(p.Name, ToCanonical(p.Value)));
                    return new JObject(props);
                case JTokenType.Array:
                    var arr = (JArray)token;
                    return new JArray(arr.Select(ToCanonical));
                default:
                    return token;
            }
        }

        #endregion

        #region 辅助 - SM4密钥派生

        private static string DeriveSm4Key16(string appId, string appSecret)
        {
            // 以appId(渠道id)作为Key，对appSecret加密，得到新秘钥串
            string appIdKey16 = NormalizeSm4Key(appId);
            string newKeyStrBase64 = SM4Util.EncryptEcb(appSecret, appIdKey16);

            // 去除=号，取前32位，不足补0
            string cleaned = newKeyStrBase64.Replace("=", string.Empty);
            if (cleaned.Length < 32) cleaned = cleaned.PadRight(32, '0');
            string first32 = cleaned.Substring(0, 32);

            // 实际底层取前16位作为真正的SM4密钥
            string final16 = first32.Substring(0, 16);
            return final16;
        }

        private static string NormalizeSm4Key(string src)
        {
            if (string.IsNullOrEmpty(src)) src = string.Empty;
            // 取前16字节，不足补0
            var bytes = Encoding.UTF8.GetBytes(src);
            if (bytes.Length == 16) return Encoding.UTF8.GetString(bytes);
            if (bytes.Length > 16) return Encoding.UTF8.GetString(bytes, 0, 16);

            var padded = new byte[16];
            Array.Copy(bytes, padded, bytes.Length);
            return Encoding.UTF8.GetString(padded);
        }

        #endregion
    }
}
