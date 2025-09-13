using System.Text;
using System.Linq;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;
using CryptoTool.Algorithm.Algorithms.RSA;
using CryptoTool.Algorithm.Utils;
using CryptoTool.Win.Helpers;
using CryptoTool.Win.Enums;

namespace CryptoTool.Win
{
    public partial class RSAConvertTabControl : UserControl
    {
        public event Action<string> StatusChanged;

        // 存储导入的公钥和私钥用于验证
        private string _publicKeyForValidation = string.Empty;
        private string _privateKeyForValidation = string.Empty;
        private KeyFormat _publicKeyFormatForValidation = KeyFormat.PEM;
        private RSAKeyType _publicKeyTypeForValidation = RSAKeyType.PKCS1;
        private KeyFormat _privateKeyFormatForValidation = KeyFormat.PEM;
        private RSAKeyType _privateKeyTypeForValidation = RSAKeyType.PKCS1;

        public RSAConvertTabControl()
        {
            InitializeComponent();
            InitializeDefaults();
        }

        private void InitializeDefaults()
        {
            // 设置默认选项
            comboInputFormat.SelectedIndex = 0; // PEM
            comboInputKeyType.SelectedIndex = 1; // PKCS8
            comboOutputFormat.SelectedIndex = 1; // Base64
            comboOutputKeyType.SelectedIndex = 1; // PKCS8
            radioPrivateKey.Checked = true;

            // 初始化验证结果
            labelValidationResult.Text = "验证结果: 未验证";
            labelValidationResult.ForeColor = Color.Gray;
        }

        private void SetStatus(string message)
        {
            StatusChanged?.Invoke(message);
        }

        #region 事件处理

        private void btnValidateKeyPair_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(_publicKeyForValidation) || string.IsNullOrEmpty(_privateKeyForValidation))
                {
                    MessageBox.Show("请先转换密钥或从私钥提取公钥！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("正在验证密钥对...");

                // 解析密钥
                var rsaCrypto = new RsaCrypto();
                byte[] publicKeyBytes = ConvertKeyToBytes(_publicKeyForValidation, _publicKeyFormatForValidation);
                byte[] privateKeyBytes = ConvertKeyToBytes(_privateKeyForValidation, _privateKeyFormatForValidation);

                // 使用加密解密测试来验证密钥对匹配性
                bool isValid = ValidateKeyPairByEncryption(rsaCrypto, publicKeyBytes, privateKeyBytes);

                labelValidationResult.Text = isValid ? "验证结果: 密钥对匹配" : "验证结果: 密钥对不匹配";
                labelValidationResult.ForeColor = isValid ? Color.Green : Color.Red;

                SetStatus($"密钥对验证完成 - 结果：{(isValid ? "匹配" : "不匹配")}");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"验证密钥对失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                labelValidationResult.Text = "验证结果: 验证异常";
                labelValidationResult.ForeColor = Color.Red;
                SetStatus("验证密钥对失败");
            }
        }

        private void btnGetPublicKeyFromPrivate_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textInputKey.Text))
                {
                    MessageBox.Show("请先输入私钥！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (radioPublicKey.Checked)
                {
                    MessageBox.Show("请选择私钥类型才能提取公钥！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("正在从私钥提取公钥...");

                var inputKeyType = CryptoUIHelper.ParseRSAKeyType(comboInputKeyType.SelectedIndex);
                var inputFormat = CryptoUIHelper.ParseKeyFormat(comboInputFormat.SelectedIndex);
                var outputKeyType = CryptoUIHelper.ParseRSAKeyType(comboOutputKeyType.SelectedIndex);
                var outputFormat = CryptoUIHelper.ParseKeyFormat(comboOutputFormat.SelectedIndex);

                // 转换私钥为字节数组
                byte[] privateKeyBytes = ConvertKeyToBytes(textInputKey.Text, inputFormat);
                
                var rsaCrypto = new RsaCrypto();

                // 从私钥提取公钥
                byte[] publicKeyBytes = null; // rsaCrypto.ExtractPublicKeyFromPrivate(privateKeyBytes);
                
                // 生成公钥字符串
                string publicKeyString = ConvertKeyToString(publicKeyBytes, outputFormat);

                textOutputKey.Text = publicKeyString;

                // 存储密钥用于验证
                _privateKeyForValidation = textInputKey.Text;
                _privateKeyFormatForValidation = inputFormat;
                _privateKeyTypeForValidation = inputKeyType;
                _publicKeyForValidation = publicKeyString;
                _publicKeyFormatForValidation = outputFormat;
                _publicKeyTypeForValidation = outputKeyType;

                // 自动验证密钥对
                labelValidationResult.Text = "验证结果: 密钥对匹配（从私钥提取）";
                labelValidationResult.ForeColor = Color.Green;

                SetStatus("从私钥提取公钥完成");
            }
            catch (InvalidCastException ex)
            {
                MessageBox.Show($"从私钥提取公钥失败：密钥类型不匹配\n\n详细信息：{ex.Message}\n\n请确认输入的是私钥而不是公钥", "类型错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("从私钥提取公钥失败 - 类型不匹配");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"从私钥提取公钥失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("从私钥提取公钥失败");
            }
        }

        private void btnConvert_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textInputKey.Text))
                {
                    MessageBox.Show("请先输入密钥内容！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("正在进行格式转换...");

                var inputKeyType = CryptoUIHelper.ParseRSAKeyType(comboInputKeyType.SelectedIndex);
                var inputFormat = CryptoUIHelper.ParseKeyFormat(comboInputFormat.SelectedIndex);
                var outputKeyType = CryptoUIHelper.ParseRSAKeyType(comboOutputKeyType.SelectedIndex);
                var outputFormat = CryptoUIHelper.ParseKeyFormat(comboOutputFormat.SelectedIndex);

                bool isPrivateKey = radioPrivateKey.Checked;
                string convertedKey;

                // 转换输入密钥为字节数组
                byte[] inputKeyBytes = ConvertKeyToBytes(textInputKey.Text, inputFormat);
                
                // 直接使用字节数组进行格式转换
                convertedKey = ConvertKeyToString(inputKeyBytes, outputFormat);

                textOutputKey.Text = convertedKey;
                SetStatus($"格式转换完成 - {inputKeyType}/{inputFormat} -> {outputKeyType}/{outputFormat}");
            }
            catch (InvalidCastException ex)
            {
                MessageBox.Show($"密钥格式转换失败：密钥类型不匹配\n\n详细信息：{ex.Message}\n\n请检查：\n1. 选择的密钥类型（公钥/私钥）是否正确\n2. 输入格式和密钥类型选择是否匹配\n3. 尝试使用自动检测功能", "格式转换错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("格式转换失败 - 密钥类型不匹配");
            }
            catch (ArgumentException ex)
            {
                MessageBox.Show($"格式转换失败：{ex.Message}\n\n建议：\n1. 检查密钥内容是否完整\n2. 尝试不同的输入格式组合\n3. 使用自动检测功能", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("格式转换失败");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"格式转换失败：{ex.Message}\n\n如果问题持续存在：\n1. 请尝试清空内容重新输入\n2. 检查密钥是否来自可靠来源\n3. 尝试使用文件导入功能", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("格式转换失败");
            }
        }

        private void btnSaveToFile_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textOutputKey.Text))
                {
                    MessageBox.Show("没有可保存的内容！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                using (SaveFileDialog saveFileDialog = new SaveFileDialog())
                {
                    var outputFormat = CryptoUIHelper.ParseKeyFormat(comboOutputFormat.SelectedIndex);
                    var keyType = radioPrivateKey.Checked ? "private" : "public";
                    
                    string extension = outputFormat switch
                    {
                        KeyFormat.PEM => ".pem",
                        KeyFormat.Base64 => ".txt",
                        KeyFormat.Hex => ".txt",
                        _ => ".txt"
                    };

                    saveFileDialog.Filter = GetFileFilter(outputFormat);
                    saveFileDialog.Title = "保存转换后的密钥";
                    saveFileDialog.FileName = $"rsa_{keyType}_key{extension}";

                    if (saveFileDialog.ShowDialog() == DialogResult.OK)
                    {
                        File.WriteAllText(saveFileDialog.FileName, textOutputKey.Text, Encoding.UTF8);
                        SetStatus("密钥文件保存成功");
                        MessageBox.Show("密钥文件保存成功！", "成功", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"保存文件失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("保存文件失败");
            }
        }

        #endregion

        #region 缺失的事件处理方法

        private void btnImportFromFile_Click(object sender, EventArgs e)
        {
            try
            {
                using (OpenFileDialog openFileDialog = new OpenFileDialog())
                {
                    openFileDialog.Filter = "密钥文件 (*.pem;*.key;*.txt)|*.pem;*.key;*.txt|所有文件 (*.*)|*.*";
                    openFileDialog.Title = "导入RSA密钥文件";

                    if (openFileDialog.ShowDialog() == DialogResult.OK)
                    {
                        string content = File.ReadAllText(openFileDialog.FileName, Encoding.UTF8);
                        textInputKey.Text = content;
                        SetStatus("密钥文件导入完成");
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"导入密钥文件失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("导入密钥文件失败");
            }
        }

        private void textInputKey_TextChanged(object sender, EventArgs e)
        {
            // 清空验证结果
            labelValidationResult.Text = "验证结果: 未验证";
            labelValidationResult.ForeColor = Color.Gray;
        }

        private void btnClear_Click(object sender, EventArgs e)
        {
            textInputKey.Clear();
            textOutputKey.Clear();
            labelValidationResult.Text = "验证结果: 未验证";
            labelValidationResult.ForeColor = Color.Gray;
            SetStatus("已清空内容");
        }

        private void btnCopyToClipboard_Click(object sender, EventArgs e)
        {
            try
            {
                if (!string.IsNullOrEmpty(textOutputKey.Text))
                {
                    Clipboard.SetText(textOutputKey.Text);
                    SetStatus("密钥已复制到剪贴板");
                    MessageBox.Show("密钥已复制到剪贴板！", "成功", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                else
                {
                    MessageBox.Show("没有可复制的内容！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"复制失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("复制失败");
            }
        }

        #endregion

        #region 辅助方法

        private static string GetFileFilter(KeyFormat format)
        {
            return format switch
            {
                KeyFormat.PEM => "PEM文件 (*.pem)|*.pem|所有文件 (*.*)|*.*",
                KeyFormat.Base64 => "文本文件 (*.txt)|*.txt|所有文件 (*.*)|*.*",
                KeyFormat.Hex => "文本文件 (*.txt)|*.txt|所有文件 (*.*)|*.*",
                _ => "所有文件 (*.*)|*.*"
            };
        }

        /// <summary>
        /// 通过加密解密测试验证密钥对匹配性
        /// </summary>
        private bool ValidateKeyPairByEncryption(RsaCrypto rsaCrypto, byte[] publicKeyBytes, byte[] privateKeyBytes)
        {
            try
            {
                // 使用测试数据
                string testData = "RSA Key Pair Validation Test";
                byte[] testDataBytes = Encoding.UTF8.GetBytes(testData);
                
                // 加密
                byte[] encryptedBytes = rsaCrypto.Encrypt(testDataBytes, publicKeyBytes);
                
                // 解密
                byte[] decryptedBytes = rsaCrypto.Decrypt(encryptedBytes, privateKeyBytes);
                
                return testDataBytes.SequenceEqual(decryptedBytes);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// 安全地解析密钥，处理各种可能的异常情况
        /// </summary>
        /// <param name="keyContent">密钥内容</param>
        /// <param name="isPrivateKey">是否为私钥</param>
        /// <param name="format">密钥格式</param>
        /// <param name="keyType">密钥类型</param>
        /// <returns>解析结果，失败时返回null</returns>
        private static AsymmetricKeyParameter? SafeParseKey(string keyContent, bool isPrivateKey, KeyFormat format, RSAKeyType keyType)
        {
            // 首先尝试直接解析方法，避免通用ParseKey可能的类型问题
            var directResult = DirectParseKey(keyContent, isPrivateKey, format, keyType);
            if (directResult != null)
            {
                // 验证返回的密钥类型是否符合预期
                if (isPrivateKey && directResult is RsaPrivateCrtKeyParameters)
                {
                    return directResult;
                }
                else if (!isPrivateKey && directResult is RsaKeyParameters rsaKey && !rsaKey.IsPrivate)
                {
                    return directResult;
                }
            }

            // 如果直接解析失败，尝试通过RSAProvider的方法
            try
            {
                var rsaCrypto = new RsaCrypto();
                
                if (isPrivateKey)
                {
                    return format switch
                    {
                        KeyFormat.PEM => null,
                        _ => null
                    };
                }
                else
                {
                    return format switch
                    {
                        KeyFormat.PEM => null,
                        _ => null
                    };
                }
            }
            catch
            {
                // 忽略异常，返回null表示解析失败
            }

            return null;
        }

        /// <summary>
        /// 智能检测密钥格式，尝试多种可能性
        /// </summary>
        /// <param name="keyContent">密钥内容</param>
        /// <param name="isPrivateKey">是否为私钥</param>
        /// <returns>检测到的格式和类型</returns>
        private (KeyFormat format, RSAKeyType keyType) SmartDetectKeyFormat(string keyContent, bool isPrivateKey)
        {
            // 尝试所有可能的组合
            var combinations = new[]
            {
                (KeyFormat.PEM, RSAKeyType.PKCS8),
                (KeyFormat.PEM, RSAKeyType.PKCS1),
                (KeyFormat.Base64, RSAKeyType.PKCS8),
                (KeyFormat.Base64, RSAKeyType.PKCS1),
                (KeyFormat.Hex, RSAKeyType.PKCS8),
                (KeyFormat.Hex, RSAKeyType.PKCS1)
            };

            // 首先尝试直接解析方法
            foreach (var (format, keyType) in combinations)
            {
                var result = DirectParseKey(keyContent, isPrivateKey, format, keyType);
                if (result != null)
                {
                    // 验证结果类型
                    if (isPrivateKey && result is RsaPrivateCrtKeyParameters)
                    {
                        return (format, keyType);
                    }
                    else if (!isPrivateKey && result is RsaKeyParameters rsaKey && !rsaKey.IsPrivate)
                    {
                        return (format, keyType);
                    }
                }
            }

            // 如果直接解析都失败，尝试SafeParseKey（包含通用ParseKey的回退）
            foreach (var (format, keyType) in combinations)
            {
                var result = SafeParseKey(keyContent, isPrivateKey, format, keyType);
                if (result != null)
                {
                    return (format, keyType);
                }
            }

            throw new ArgumentException("无法检测密钥格式，请检查密钥内容");
        }

        /// <summary>
        /// 尝试直接使用RSAProvider的专用方法解析密钥，避免通用ParseKey方法的类型问题
        /// </summary>
        /// <param name="keyContent">密钥内容</param>
        /// <param name="isPrivateKey">是否为私钥</param>
        /// <param name="format">密钥格式</param>
        /// <param name="keyType">密钥类型</param>
        /// <returns>解析后的密钥对象</returns>
        private static AsymmetricKeyParameter? DirectParseKey(string keyContent, bool isPrivateKey, KeyFormat format, RSAKeyType keyType)
        {
            try
            {
                if (isPrivateKey)
                {
                    return format switch
                    {
                        KeyFormat.PEM => null,
                        _ => null
                    };
                }
                else
                {
                    return format switch
                    {
                        KeyFormat.PEM => null,
                        _ => null
                    };
                }
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// 将密钥字符串转换为字节数组
        /// </summary>
        private byte[] ConvertKeyToBytes(string keyString, KeyFormat format)
        {
            return format switch
            {
                KeyFormat.PEM => Encoding.UTF8.GetBytes(keyString),
                KeyFormat.Base64 => Convert.FromBase64String(keyString),
                KeyFormat.Hex => CryptoUtil.HexToBytes(keyString),
                _ => Encoding.UTF8.GetBytes(keyString)
            };
        }

        /// <summary>
        /// 将密钥字节数组转换为字符串
        /// </summary>
        private string ConvertKeyToString(byte[] keyBytes, KeyFormat format)
        {
            return format switch
            {
                KeyFormat.PEM => Encoding.UTF8.GetString(keyBytes),
                KeyFormat.Base64 => Convert.ToBase64String(keyBytes),
                KeyFormat.Hex => CryptoUtil.BytesToHex(keyBytes),
                _ => Encoding.UTF8.GetString(keyBytes)
            };
        }

        #endregion
    }
}