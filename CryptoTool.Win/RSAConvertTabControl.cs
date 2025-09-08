using CryptoTool.Common;
using System.Text;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;

namespace CryptoTool.Win
{
    public partial class RSAConvertTabControl : UserControl
    {
        public event Action<string> StatusChanged;

        // 存储导入的公钥和私钥用于验证
        private string _publicKeyForValidation = string.Empty;
        private string _privateKeyForValidation = string.Empty;
        private RSAUtil.RSAKeyFormat _publicKeyFormatForValidation = RSAUtil.RSAKeyFormat.PEM;
        private RSAUtil.RSAKeyType _publicKeyTypeForValidation = RSAUtil.RSAKeyType.PKCS1;
        private RSAUtil.RSAKeyFormat _privateKeyFormatForValidation = RSAUtil.RSAKeyFormat.PEM;
        private RSAUtil.RSAKeyType _privateKeyTypeForValidation = RSAUtil.RSAKeyType.PKCS1;

        public RSAConvertTabControl()
        {
            InitializeComponent();
            InitializeDefaults();
        }

        private void InitializeDefaults()
        {
            // 初始化默认值
            comboInputKeyType.SelectedIndex = 0; // PKCS1
            comboInputFormat.SelectedIndex = 0; // PEM
            comboOutputKeyType.SelectedIndex = 1; // PKCS8
            comboOutputFormat.SelectedIndex = 0; // PEM
            radioPrivateKey.Checked = true; // 默认选择私钥

            // 初始化验证结果标签
            labelValidationResult.Text = "验证结果: 等待验证";
            labelValidationResult.ForeColor = Color.Gray;
        }

        private void SetStatus(string message)
        {
            StatusChanged?.Invoke(message);
        }

        #region 事件处理

        private void btnImportFromFile_Click(object sender, EventArgs e)
        {
            try
            {
                using (OpenFileDialog openFileDialog = new OpenFileDialog())
                {
                    openFileDialog.Filter = "密钥文件 (*.txt;*.key;*.pem;*.pub)|*.txt;*.key;*.pem;*.pub|所有文件 (*.*)|*.*";
                    openFileDialog.Title = "导入RSA密钥文件";

                    if (openFileDialog.ShowDialog() == DialogResult.OK)
                    {
                        string content = File.ReadAllText(openFileDialog.FileName, Encoding.UTF8);
                        textInputKey.Text = content.Trim();
                        
                        // 根据文件内容自动判断密钥类型
                        AutoDetectKeyType(content);
                        
                        SetStatus("密钥文件导入成功");
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"导入密钥文件失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("导入密钥文件失败");
            }
        }

        private void btnValidateKeyPair_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(_publicKeyForValidation) || string.IsNullOrEmpty(_privateKeyForValidation))
                {
                    MessageBox.Show("请先分别导入公钥和私钥进行验证！\n\n操作步骤：\n1. 导入私钥并点击「从私钥提取公钥」\n2. 或分别导入公钥和私钥文件", "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }

                SetStatus("正在验证密钥对一致性...");

                bool isValid = RSAUtil.ValidateKeyPair(_publicKeyForValidation, _privateKeyForValidation, 
                    _publicKeyFormatForValidation, _publicKeyTypeForValidation,
                    _privateKeyFormatForValidation, _privateKeyTypeForValidation);

                labelValidationResult.Text = $"验证结果: {(isValid ? "密钥对匹配" : "密钥对不匹配")}";
                labelValidationResult.ForeColor = isValid ? Color.Green : Color.Red;

                SetStatus($"密钥对验证完成 - {(isValid ? "匹配" : "不匹配")}");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"密钥对验证失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                labelValidationResult.Text = "验证结果: 验证异常";
                labelValidationResult.ForeColor = Color.Red;
                SetStatus("密钥对验证失败");
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

                var inputKeyType = (RSAUtil.RSAKeyType)comboInputKeyType.SelectedIndex;
                var inputFormat = (RSAUtil.RSAKeyFormat)comboInputFormat.SelectedIndex;
                var outputKeyType = (RSAUtil.RSAKeyType)comboOutputKeyType.SelectedIndex;
                var outputFormat = (RSAUtil.RSAKeyFormat)comboOutputFormat.SelectedIndex;

                // 尝试解析私钥，如果失败则使用智能检测
                AsymmetricKeyParameter? keyParam = SafeParseKey(textInputKey.Text, true, inputFormat, inputKeyType);
                
                if (keyParam == null)
                {
                    // 如果解析失败，尝试智能检测
                    var (detectedFormat, detectedType) = SmartDetectKeyFormat(textInputKey.Text, true);
                    keyParam = SafeParseKey(textInputKey.Text, true, detectedFormat, detectedType);
                    
                    if (keyParam != null)
                    {
                        // 更新UI显示检测到的格式
                        comboInputFormat.SelectedIndex = (int)detectedFormat;
                        comboInputKeyType.SelectedIndex = (int)detectedType;
                        inputFormat = detectedFormat;
                        inputKeyType = detectedType;
                        SetStatus("使用智能检测重新解析私钥成功");
                    }
                    else
                    {
                        throw new ArgumentException("无法解析私钥，请检查密钥内容和格式选择");
                    }
                }

                var privateKey = (RsaPrivateCrtKeyParameters)keyParam;

                // 从私钥获取公钥参数
                var publicKey = new RsaKeyParameters(false, privateKey.Modulus, privateKey.PublicExponent);

                // 生成公钥字符串
                string publicKeyString = RSAUtil.GeneratePublicKeyString(publicKey, outputFormat, outputKeyType);

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

                var inputKeyType = (RSAUtil.RSAKeyType)comboInputKeyType.SelectedIndex;
                var inputFormat = (RSAUtil.RSAKeyFormat)comboInputFormat.SelectedIndex;
                var outputKeyType = (RSAUtil.RSAKeyType)comboOutputKeyType.SelectedIndex;
                var outputFormat = (RSAUtil.RSAKeyFormat)comboOutputFormat.SelectedIndex;

                bool isPrivateKey = radioPrivateKey.Checked;
                string convertedKey;

                // 尝试使用更安全的解析方法
                if (isPrivateKey)
                {
                    // 尝试安全解析私钥
                    var keyParam = SafeParseKey(textInputKey.Text, true, inputFormat, inputKeyType);
                    
                    if (keyParam == null)
                    {
                        // 如果解析失败，尝试智能检测
                        var (detectedFormat, detectedType) = SmartDetectKeyFormat(textInputKey.Text, true);
                        keyParam = SafeParseKey(textInputKey.Text, true, detectedFormat, detectedType);
                        
                        if (keyParam != null)
                        {
                            // 更新UI显示检测到的格式
                            comboInputFormat.SelectedIndex = (int)detectedFormat;
                            comboInputKeyType.SelectedIndex = (int)detectedType;
                            inputFormat = detectedFormat;
                            inputKeyType = detectedType;
                            SetStatus("使用智能检测重新解析密钥成功");
                        }
                        else
                        {
                            throw new ArgumentException("无法解析私钥，请检查密钥内容和格式选择");
                        }
                    }

                    // 确保是正确的私钥类型
                    if (keyParam is RsaPrivateCrtKeyParameters privateKey)
                    {
                        convertedKey = RSAUtil.GeneratePrivateKeyString(privateKey, outputFormat, outputKeyType);
                    }
                    else
                    {
                        throw new InvalidCastException($"解析的密钥类型不匹配，期望RsaPrivateCrtKeyParameters，实际得到{keyParam.GetType().Name}");
                    }
                }
                else
                {
                    // 尝试安全解析公钥
                    var keyParam = SafeParseKey(textInputKey.Text, false, inputFormat, inputKeyType);
                    
                    if (keyParam == null)
                    {
                        // 如果解析失败，尝试智能检测
                        var (detectedFormat, detectedType) = SmartDetectKeyFormat(textInputKey.Text, false);
                        keyParam = SafeParseKey(textInputKey.Text, false, detectedFormat, detectedType);
                        
                        if (keyParam != null)
                        {
                            // 更新UI显示检测到的格式
                            comboInputFormat.SelectedIndex = (int)detectedFormat;
                            comboInputKeyType.SelectedIndex = (int)detectedType;
                            inputFormat = detectedFormat;
                            inputKeyType = detectedType;
                            SetStatus("使用智能检测重新解析密钥成功");
                        }
                        else
                        {
                            throw new ArgumentException("无法解析公钥，请检查密钥内容和格式选择");
                        }
                    }

                    // 确保是正确的公钥类型
                    if (keyParam is RsaKeyParameters publicKey)
                    {
                        convertedKey = RSAUtil.GeneratePublicKeyString(publicKey, outputFormat, outputKeyType);
                    }
                    else
                    {
                        throw new InvalidCastException($"解析的密钥类型不匹配，期望RsaKeyParameters，实际得到{keyParam.GetType().Name}");
                    }
                }

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

        private void btnClear_Click(object sender, EventArgs e)
        {
            textInputKey.Clear();
            textOutputKey.Clear();
            labelValidationResult.Text = "验证结果: 等待验证";
            labelValidationResult.ForeColor = Color.Gray;
            _publicKeyForValidation = string.Empty;
            _privateKeyForValidation = string.Empty;
            SetStatus("已清空所有内容");
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
                    var outputFormat = (RSAUtil.RSAKeyFormat)comboOutputFormat.SelectedIndex;
                    var keyType = radioPrivateKey.Checked ? "private" : "public";
                    
                    string extension = outputFormat switch
                    {
                        RSAUtil.RSAKeyFormat.PEM => ".pem",
                        RSAUtil.RSAKeyFormat.Base64 => ".txt",
                        RSAUtil.RSAKeyFormat.Hex => ".txt",
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

        private void btnCopyToClipboard_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textOutputKey.Text))
                {
                    MessageBox.Show("没有可复制的内容！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                Clipboard.SetText(textOutputKey.Text);
                SetStatus("已复制到剪贴板");
                MessageBox.Show("已复制到剪贴板！", "成功", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"复制到剪贴板失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("复制到剪贴板失败");
            }
        }

        private void textInputKey_TextChanged(object sender, EventArgs e)
        {
            // 当输入密钥内容改变时，自动检测密钥类型
            if (!string.IsNullOrEmpty(textInputKey.Text))
            {
                AutoDetectKeyType(textInputKey.Text);
            }
            else
            {
                // 清空验证结果
                labelValidationResult.Text = "验证结果: 等待验证";
                labelValidationResult.ForeColor = Color.Gray;
                _publicKeyForValidation = string.Empty;
                _privateKeyForValidation = string.Empty;
            }
        }

        #endregion

        #region 辅助方法

        private void AutoDetectKeyType(string keyContent)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(keyContent))
                    return;

                bool isPrivateKey = radioPrivateKey.Checked && !radioPublicKey.Checked;

                // 使用智能检测来确定最佳的格式和类型组合
                var (detectedFormat, detectedType) = SmartDetectKeyFormat(keyContent, isPrivateKey);

                // 更新UI选择
                comboInputFormat.SelectedIndex = (int)detectedFormat;
                comboInputKeyType.SelectedIndex = (int)detectedType;

                // 存储检测结果用于验证
                if (isPrivateKey)
                {
                    _privateKeyForValidation = keyContent;
                    _privateKeyFormatForValidation = detectedFormat;
                    _privateKeyTypeForValidation = detectedType;
                }
                else
                {
                    _publicKeyForValidation = keyContent;
                    _publicKeyFormatForValidation = detectedFormat;
                    _publicKeyTypeForValidation = detectedType;
                }

                SetStatus($"密钥类型自动检测成功 - {detectedType}/{detectedFormat}");
            }
            catch
            {
                // 自动检测失败时保持默认值
                SetStatus("无法自动检测密钥类型，请手动选择");
            }
        }

        private static string GetFileFilter(RSAUtil.RSAKeyFormat format)
        {
            return format switch
            {
                RSAUtil.RSAKeyFormat.PEM => "PEM文件 (*.pem)|*.pem|所有文件 (*.*)|*.*",
                RSAUtil.RSAKeyFormat.Base64 => "文本文件 (*.txt)|*.txt|所有文件 (*.*)|*.*",
                RSAUtil.RSAKeyFormat.Hex => "文本文件 (*.txt)|*.txt|所有文件 (*.*)|*.*",
                _ => "所有文件 (*.*)|*.*"
            };
        }

        /// <summary>
        /// 安全地解析密钥，处理各种可能的异常情况
        /// </summary>
        /// <param name="keyContent">密钥内容</param>
        /// <param name="isPrivateKey">是否为私钥</param>
        /// <param name="format">密钥格式</param>
        /// <param name="keyType">密钥类型</param>
        /// <returns>解析结果，失败时返回null</returns>
        private static AsymmetricKeyParameter? SafeParseKey(string keyContent, bool isPrivateKey, RSAUtil.RSAKeyFormat format, RSAUtil.RSAKeyType keyType)
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

            // 如果直接解析失败，尝试通用ParseKey方法
            try
            {
                AsymmetricKeyParameter result = RSAUtil.ParseKey(keyContent, isPrivateKey, format, keyType);
                
                // 验证返回的密钥类型是否符合预期
                if (isPrivateKey)
                {
                    // 对于私钥，确保返回的是RsaPrivateCrtKeyParameters类型
                    if (result is RsaPrivateCrtKeyParameters)
                    {
                        return result;
                    }
                }
                else
                {
                    // 对于公钥，确保返回的是RsaKeyParameters类型
                    if (result is RsaKeyParameters rsaKey && !rsaKey.IsPrivate)
                    {
                        return result;
                    }
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
        private (RSAUtil.RSAKeyFormat format, RSAUtil.RSAKeyType keyType) SmartDetectKeyFormat(string keyContent, bool isPrivateKey)
        {
            // 尝试所有可能的组合
            var combinations = new[]
            {
                (RSAUtil.RSAKeyFormat.PEM, RSAUtil.RSAKeyType.PKCS8),
                (RSAUtil.RSAKeyFormat.PEM, RSAUtil.RSAKeyType.PKCS1),
                (RSAUtil.RSAKeyFormat.Base64, RSAUtil.RSAKeyType.PKCS8),
                (RSAUtil.RSAKeyFormat.Base64, RSAUtil.RSAKeyType.PKCS1),
                (RSAUtil.RSAKeyFormat.Hex, RSAUtil.RSAKeyType.PKCS8),
                (RSAUtil.RSAKeyFormat.Hex, RSAUtil.RSAKeyType.PKCS1)
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
        /// 尝试直接使用RSAUtil的专用方法解析密钥，避免通用ParseKey方法的类型问题
        /// </summary>
        /// <param name="keyContent">密钥内容</param>
        /// <param name="isPrivateKey">是否为私钥</param>
        /// <param name="format">密钥格式</param>
        /// <param name="keyType">密钥类型</param>
        /// <returns>解析后的密钥对象</returns>
        private static AsymmetricKeyParameter? DirectParseKey(string keyContent, bool isPrivateKey, RSAUtil.RSAKeyFormat format, RSAUtil.RSAKeyType keyType)
        {
            try
            {
                if (isPrivateKey)
                {
                    return format switch
                    {
                        RSAUtil.RSAKeyFormat.PEM => RSAUtil.ParsePrivateKeyFromPem(keyContent),
                        RSAUtil.RSAKeyFormat.Base64 => RSAUtil.ParsePrivateKeyFromBase64(keyContent, keyType),
                        RSAUtil.RSAKeyFormat.Hex => RSAUtil.ParsePrivateKeyFromHex(keyContent, keyType),
                        _ => null
                    };
                }
                else
                {
                    return format switch
                    {
                        RSAUtil.RSAKeyFormat.PEM => RSAUtil.ParsePublicKeyFromPem(keyContent),
                        RSAUtil.RSAKeyFormat.Base64 => RSAUtil.ParsePublicKeyFromBase64(keyContent, keyType),
                        RSAUtil.RSAKeyFormat.Hex => RSAUtil.ParsePublicKeyFromHex(keyContent, keyType),
                        _ => null
                    };
                }
            }
            catch
            {
                return null;
            }
        }
        #endregion
    }
}