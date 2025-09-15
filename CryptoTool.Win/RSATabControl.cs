using CryptoTool.Algorithm.Algorithms.RSA;
using CryptoTool.Win.Helpers;
using System.Text;

namespace CryptoTool.Win
{
    public partial class RSATabControl : UserControl
    {
        public event Action<string> StatusChanged;

        public RSATabControl()
        {
            InitializeComponent();
            InitializeDefaults();
        }

        private void InitializeDefaults()
        {
            // 初始化默认值
            comboRSAKeySize.SelectedIndex = 1; // 2048
            comboRSAKeyFormat.SelectedIndex = 1; // pkcs#8
            comboRSAKeyPadding.SelectedIndex = 0; // PKCS1
            comboRSAKeyOutputFormat.SelectedIndex = 1; // base64
            comboRSAEncryptOutputFormat.SelectedIndex = 0; // base64
            comboRSASignAlgmFormat.SelectedIndex = 1; // SHA256withRSA(RSA2)
            comboRSASignOutputFormat.SelectedIndex = 0; // base64
        }

        private void SetStatus(string message)
        {
            StatusChanged?.Invoke(message);
        }

        #region RSA功能

        private void btnGenerateRSAKey_Click(object sender, EventArgs e)
        {
            try
            {
                SetStatus("正在生成RSA密钥对...");

                string keySizeStr = comboRSAKeySize.SelectedItem.ToString();
                var keyFormat = comboRSAKeyFormat.SelectedItem.ToString().ToLower();
                var keyOutputFormat = comboRSAKeyOutputFormat.SelectedItem.ToString().ToLower();
                if (keyOutputFormat.ToLowerInvariant() == "pem")
                {
                    MessageBox.Show($"RSA密钥生成失败，暂不支持{keyOutputFormat}格式显示！", "失败", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    textRSAPublicKey.Text = "";
                    textRSAPrivateKey.Text = "";
                    return;
                }
                int keySize = int.Parse(keySizeStr);

                var rsaCrypto = new RsaCrypto(keySize, keyFormat);
                var keyPair = rsaCrypto.GenerateKeyPair();

                var uiOutputFormat = FormatConversionHelper.ParseOutputFormat(keyOutputFormat);
                textRSAPublicKey.Text = FormatConversionHelper.BytesToString(keyPair.PublicKey, uiOutputFormat);
                textRSAPrivateKey.Text = FormatConversionHelper.BytesToString(keyPair.PrivateKey, uiOutputFormat);

                SetStatus($"RSA密钥对生成完成 - {keySize}位 {comboRSAKeyFormat.SelectedItem}格式");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"生成RSA密钥对失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("生成RSA密钥对失败");
            }
        }

        private void btnImportRSAKey_Click(object sender, EventArgs e)
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
                        string[] lines = content.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);

                        if (lines.Length >= 2)
                        {
                            textRSAPublicKey.Text = lines[0].Trim();
                            textRSAPrivateKey.Text = lines[1].Trim();
                        }
                        else if (lines.Length == 1)
                        {
                            string keyContent = lines[0].Trim();
                            if (keyContent.Contains("PRIVATE"))
                            {
                                textRSAPrivateKey.Text = keyContent;
                            }
                            else
                            {
                                textRSAPublicKey.Text = keyContent;
                            }
                        }

                        SetStatus("RSA密钥文件导入完成");
                        MessageBox.Show("RSA密钥文件导入完成！", "成功", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"导入RSA密钥文件失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("导入RSA密钥文件失败");
            }
        }

        private void btnExportRSAKey_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textRSAPublicKey.Text) && string.IsNullOrEmpty(textRSAPrivateKey.Text))
                {
                    MessageBox.Show("没有可导出的密钥！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                using (SaveFileDialog saveFileDialog = new SaveFileDialog())
                {
                    saveFileDialog.Filter = "密钥文件 (*.txt)|*.txt|所有文件 (*.*)|*.*";
                    saveFileDialog.Title = "导出RSA密钥文件";
                    saveFileDialog.FileName = "rsa_keypair.txt";

                    if (saveFileDialog.ShowDialog() == DialogResult.OK)
                    {
                        StringBuilder content = new StringBuilder();
                        if (!string.IsNullOrEmpty(textRSAPublicKey.Text))
                        {
                            content.AppendLine("# RSA公钥");
                            content.AppendLine(textRSAPublicKey.Text);
                            content.AppendLine();
                        }
                        if (!string.IsNullOrEmpty(textRSAPrivateKey.Text))
                        {
                            content.AppendLine("# RSA私钥");
                            content.AppendLine(textRSAPrivateKey.Text);
                        }

                        File.WriteAllText(saveFileDialog.FileName, content.ToString(), Encoding.UTF8);
                        SetStatus("RSA密钥文件导出完成");
                        MessageBox.Show("RSA密钥文件导出完成！", "成功", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"导出RSA密钥文件失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("导出RSA密钥文件失败");
            }
        }

        private void btnRSAEncrypt_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textRSAPlainText.Text))
                {
                    MessageBox.Show("请输入要加密的明文！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (string.IsNullOrEmpty(textRSAPublicKey.Text))
                {
                    MessageBox.Show("请先生成或输入RSA公钥！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("正在进行RSA加密...");

                var rsaCrypto = new RsaCrypto();
                byte[] publicKeyBytes = Convert.FromBase64String(textRSAPublicKey.Text);
                byte[] dataBytes = Encoding.UTF8.GetBytes(textRSAPlainText.Text);
                byte[] encryptedBytes = rsaCrypto.Encrypt(dataBytes, publicKeyBytes);

                textRSACipherText.Text = Convert.ToBase64String(encryptedBytes);

                SetStatus($"RSA加密完成 - 使用{comboRSAKeyPadding.SelectedItem}填充，输出{comboRSAEncryptOutputFormat.SelectedItem}格式");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"RSA加密失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("RSA加密失败");
            }
        }

        private void btnRSADecrypt_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textRSACipherText.Text))
                {
                    MessageBox.Show("请输入要解密的密文！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (string.IsNullOrEmpty(textRSAPrivateKey.Text))
                {
                    MessageBox.Show("请先生成或输入RSA私钥！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("正在进行RSA解密...");

                var rsaCrypto = new RsaCrypto();
                byte[] privateKeyBytes = Convert.FromBase64String(textRSAPrivateKey.Text);
                byte[] cipherBytes = Convert.FromBase64String(textRSACipherText.Text);
                byte[] decryptedBytes = rsaCrypto.Decrypt(cipherBytes, privateKeyBytes);

                textRSAPlainText.Text = Encoding.UTF8.GetString(decryptedBytes);

                SetStatus($"RSA解密完成 - 使用{comboRSAKeyPadding.SelectedItem}填充，输入{comboRSAEncryptOutputFormat.SelectedItem}格式");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"RSA解密失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("RSA解密失败");
            }
        }

        private void btnRSASign_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textRSASignData.Text))
                {
                    MessageBox.Show("请输入要签名的数据！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (string.IsNullOrEmpty(textRSAPrivateKey.Text))
                {
                    MessageBox.Show("请先生成或输入RSA私钥！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("正在进行RSA签名...");

                var rsaCrypto = new RsaCrypto();
                byte[] privateKeyBytes = Convert.FromBase64String(textRSAPrivateKey.Text);
                byte[] dataBytes = Encoding.UTF8.GetBytes(textRSASignData.Text);
                byte[] signatureBytes = rsaCrypto.Sign(dataBytes, privateKeyBytes);

                textRSASignature.Text = Convert.ToBase64String(signatureBytes);

                SetStatus($"RSA签名完成 - 使用{comboRSASignAlgmFormat.SelectedItem}算法，输出{comboRSASignOutputFormat.SelectedItem}格式");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"RSA签名失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("RSA签名失败");
            }
        }

        private void btnRSAVerify_Click(object sender, EventArgs e)
        {
            try
            {
                // 使用可能的控件名称
                string verifyData = "";
                string verifySignature = "";

                // 尝试查找不同的可能控件名称
                var dataControl = FindControlByName("textRSAVerifyData") ?? FindControlByName("textRSASignData");
                var signatureControl = FindControlByName("textRSAVerifySignature") ?? FindControlByName("textRSASignature");

                if (dataControl is TextBox dataTextBox)
                    verifyData = dataTextBox.Text;
                else
                {
                    MessageBox.Show("找不到验证数据输入控件！", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }

                if (signatureControl is TextBox signatureTextBox)
                    verifySignature = signatureTextBox.Text;
                else
                {
                    MessageBox.Show("找不到签名输入控件！", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }

                if (string.IsNullOrEmpty(verifyData))
                {
                    MessageBox.Show("请输入要验证的数据！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (string.IsNullOrEmpty(verifySignature))
                {
                    MessageBox.Show("请输入要验证的签名！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (string.IsNullOrEmpty(textRSAPublicKey.Text))
                {
                    MessageBox.Show("请先生成或输入RSA公钥！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("正在进行RSA验签...");

                var rsaCrypto = new RsaCrypto();
                byte[] publicKeyBytes = Convert.FromBase64String(textRSAPublicKey.Text);
                byte[] dataBytes = Encoding.UTF8.GetBytes(verifyData);
                byte[] signatureBytes = Convert.FromBase64String(verifySignature);
                bool isValid = rsaCrypto.VerifySign(dataBytes, signatureBytes, publicKeyBytes);

                labelRSAVerifyResult.Text = isValid ? "验证通过" : "验证失败";
                labelRSAVerifyResult.ForeColor = isValid ? Color.Green : Color.Red;

                SetStatus($"RSA验签完成 - 结果：{(isValid ? "通过" : "失败")}");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"RSA验签失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                labelRSAVerifyResult.Text = "验证异常";
                labelRSAVerifyResult.ForeColor = Color.Red;
                SetStatus("RSA验签失败");
            }
        }

        #endregion

        #region 辅助方法

        /// <summary>
        /// 通过名称查找控件
        /// </summary>
        private Control? FindControlByName(string name)
        {
            return FindControlByName(this, name);
        }

        /// <summary>
        /// 递归查找控件
        /// </summary>
        private Control? FindControlByName(Control parent, string name)
        {
            if (parent.Name == name)
                return parent;

            foreach (Control child in parent.Controls)
            {
                var found = FindControlByName(child, name);
                if (found != null)
                    return found;
            }

            return null;
        }

        #endregion

        #region 事件处理器

        private void ComboRSAEncryptOutputFormat_SelectedIndexChanged(object sender, EventArgs e)
        {
            // 输出格式改变时的处理逻辑
        }

        private void ComboRSASignOutputFormat_SelectedIndexChanged(object sender, EventArgs e)
        {
            // 签名输出格式改变时的处理逻辑
        }

        #endregion
    }
}
