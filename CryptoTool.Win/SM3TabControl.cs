using CryptoTool.Common.GM;
using System.Text;

namespace CryptoTool.Win
{
    public partial class SM3TabControl : UserControl
    {
        public event Action<string> StatusChanged;

        public SM3TabControl()
        {
            InitializeComponent();
            InitializeDefaults();
        }

        private void InitializeDefaults()
        {
            // 设置默认选项
            comboSM3DataFormat.SelectedIndex = 0; // Text
            comboSM3OutputFormat.SelectedIndex = 0; // Hex
            comboSM3FileHashFormat.SelectedIndex = 0; // Hex
            comboSM3VerifyDataFormat.SelectedIndex = 0; // Text
            comboSM3VerifyHashFormat.SelectedIndex = 0; // Hex
            comboSM3HMACDataFormat.SelectedIndex = 0; // Text
            comboSM3HMACOutputFormat.SelectedIndex = 0; // Hex

            // 设置示例数据
            textSM3Input.Text = "Hello SM3!";
            textSM3HMACData.Text = "Hello HMAC-SM3!";
            textSM3HMACKey.Text = "mySecretKey";
        }

        private void SetStatus(string message)
        {
            StatusChanged?.Invoke(message);
        }

        #region SM3哈希计算

        private void btnSM3Hash_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textSM3Input.Text))
                {
                    MessageBox.Show("请输入要计算哈希的数据！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("正在计算SM3哈希...");

                string inputData = textSM3Input.Text;
                string dataFormat = comboSM3DataFormat.SelectedItem.ToString();
                string outputFormat = comboSM3OutputFormat.SelectedItem.ToString();

                byte[] dataBytes = ConvertInputData(inputData, dataFormat);
                byte[] hashBytes = SM3Util.ComputeHash(dataBytes);
                
                string result = outputFormat switch
                {
                    "Hex" => SM3Util.BytesToHex(hashBytes),
                    "Base64" => Convert.ToBase64String(hashBytes),
                    _ => SM3Util.BytesToHex(hashBytes)
                };

                textSM3Output.Text = result;
                SetStatus($"SM3哈希计算完成 - 输入格式：{dataFormat}，输出格式：{outputFormat}");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"SM3哈希计算失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("SM3哈希计算失败");
            }
        }

        private void btnSM3Clear_Click(object sender, EventArgs e)
        {
            textSM3Input.Clear();
            textSM3Output.Clear();
            SetStatus("已清空输入和输出");
        }

        #endregion

        #region 文件哈希计算

        private void btnSM3SelectFile_Click(object sender, EventArgs e)
        {
            try
            {
                using (OpenFileDialog openFileDialog = new OpenFileDialog())
                {
                    openFileDialog.Title = "选择要计算SM3哈希的文件";
                    openFileDialog.Filter = "所有文件 (*.*)|*.*";

                    if (openFileDialog.ShowDialog() == DialogResult.OK)
                    {
                        textSM3FilePath.Text = openFileDialog.FileName;
                        SetStatus("已选择文件：" + Path.GetFileName(openFileDialog.FileName));
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"选择文件失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("选择文件失败");
            }
        }

        private void btnSM3ComputeFileHash_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textSM3FilePath.Text))
                {
                    MessageBox.Show("请先选择要计算哈希的文件！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (!File.Exists(textSM3FilePath.Text))
                {
                    MessageBox.Show("文件不存在，请重新选择！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("正在计算文件SM3哈希...");

                string outputFormat = comboSM3FileHashFormat.SelectedItem.ToString();
                
                string result = outputFormat switch
                {
                    "Hex" => SM3Util.ComputeFileHashHex(textSM3FilePath.Text),
                    "Base64" => SM3Util.ComputeFileHashBase64(textSM3FilePath.Text),
                    _ => SM3Util.ComputeFileHashHex(textSM3FilePath.Text)
                };

                textSM3FileHash.Text = result;
                
                FileInfo fileInfo = new FileInfo(textSM3FilePath.Text);
                SetStatus($"文件SM3哈希计算完成 - 文件大小：{FormatFileSize(fileInfo.Length)}，输出格式：{outputFormat}");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"计算文件哈希失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("计算文件哈希失败");
            }
        }

        #endregion

        #region 哈希值验证

        private void btnSM3Verify_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textSM3VerifyData.Text))
                {
                    MessageBox.Show("请输入要验证的原始数据！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (string.IsNullOrEmpty(textSM3VerifyHash.Text))
                {
                    MessageBox.Show("请输入期望的哈希值！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("正在验证SM3哈希值...");

                string inputData = textSM3VerifyData.Text;
                string expectedHash = textSM3VerifyHash.Text;
                string dataFormat = comboSM3VerifyDataFormat.SelectedItem.ToString();
                string hashFormat = comboSM3VerifyHashFormat.SelectedItem.ToString();

                bool verifyResult = false;

                if (hashFormat == "Hex")
                {
                    if (dataFormat == "Text")
                    {
                        verifyResult = SM3Util.VerifyHashHex(inputData, expectedHash, Encoding.UTF8);
                    }
                    else
                    {
                        byte[] dataBytes = ConvertInputData(inputData, dataFormat);
                        verifyResult = SM3Util.VerifyHashHex(dataBytes, expectedHash);
                    }
                }
                else // Base64
                {
                    byte[] expectedHashBytes = Convert.FromBase64String(expectedHash);
                    byte[] dataBytes = ConvertInputData(inputData, dataFormat);
                    verifyResult = SM3Util.VerifyHash(dataBytes, expectedHashBytes);
                }

                labelSM3VerifyResult.Text = $"验证结果: {(verifyResult ? "验证成功" : "验证失败")}";
                labelSM3VerifyResult.ForeColor = verifyResult ? Color.Green : Color.Red;

                SetStatus($"SM3哈希验证完成 - {(verifyResult ? "验证成功" : "验证失败")}");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"哈希值验证失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                labelSM3VerifyResult.Text = "验证结果: 验证异常";
                labelSM3VerifyResult.ForeColor = Color.Red;
                SetStatus("哈希值验证失败");
            }
        }

        #endregion

        #region HMAC-SM3计算

        private void btnSM3HMAC_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textSM3HMACData.Text))
                {
                    MessageBox.Show("请输入要计算HMAC的数据！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (string.IsNullOrEmpty(textSM3HMACKey.Text))
                {
                    MessageBox.Show("请输入HMAC密钥！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("正在计算HMAC-SM3...");

                string inputData = textSM3HMACData.Text;
                string key = textSM3HMACKey.Text;
                string dataFormat = comboSM3HMACDataFormat.SelectedItem.ToString();
                string outputFormat = comboSM3HMACOutputFormat.SelectedItem.ToString();

                byte[] dataBytes = ConvertInputData(inputData, dataFormat);
                byte[] keyBytes = Encoding.UTF8.GetBytes(key); // HMAC密钥通常使用UTF8编码
                
                string result = outputFormat switch
                {
                    "Hex" => SM3Util.ComputeHMacHex(dataBytes, keyBytes),
                    "Base64" => SM3Util.ComputeHMacBase64(dataBytes, keyBytes),
                    _ => SM3Util.ComputeHMacHex(dataBytes, keyBytes)
                };

                textSM3HMACOutput.Text = result;
                SetStatus($"HMAC-SM3计算完成 - 数据格式：{dataFormat}，输出格式：{outputFormat}");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"HMAC-SM3计算失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("HMAC-SM3计算失败");
            }
        }

        #endregion

        #region 辅助方法

        /// <summary>
        /// 根据格式转换输入数据为字节数组
        /// </summary>
        /// <param name="input">输入字符串</param>
        /// <param name="format">数据格式</param>
        /// <returns>字节数组</returns>
        private byte[] ConvertInputData(string input, string format)
        {
            return format switch
            {
                "Text" => Encoding.UTF8.GetBytes(input),
                "Hex" => SM3Util.HexToBytes(input),
                "Base64" => Convert.FromBase64String(input),
                _ => Encoding.UTF8.GetBytes(input)
            };
        }

        /// <summary>
        /// 格式化文件大小显示
        /// </summary>
        /// <param name="bytes">字节数</param>
        /// <returns>格式化的文件大小字符串</returns>
        private string FormatFileSize(long bytes)
        {
            const long KB = 1024;
            const long MB = KB * 1024;
            const long GB = MB * 1024;

            if (bytes >= GB)
                return $"{bytes / (double)GB:F2} GB";
            else if (bytes >= MB)
                return $"{bytes / (double)MB:F2} MB";
            else if (bytes >= KB)
                return $"{bytes / (double)KB:F2} KB";
            else
                return $"{bytes} B";
        }

        #endregion


        private void ComboSM3DataFormat_TabIndexChanged(object sender, EventArgs e)
        {
            //label1.Text = $"输入数据({comboSM3DataFormat.SelectedItem}):";
        }
        private void ComboSM3OutputFormat_TabIndexChanged(object sender, EventArgs e)
        {
            //label2.Text = $"哈希结果({comboSM3DataFormat.SelectedItem}):";
        }


        private void ComboSM3FileHashFormat_TabIndexChanged(object sender, EventArgs e)
        {
            //label4.Text = $"哈希结果({comboSM3DataFormat.SelectedItem}):";
        }

        private void ComboSM3VerifyDataFormat_TabIndexChanged(object sender, EventArgs e)
        {
            //label5.Text = $"原始数据({comboSM3DataFormat.SelectedItem}):";
        }
        private void ComboSM3VerifyHashFormat_TabIndexChanged(object sender, EventArgs e)
        {
            //label6.Text = $"期望哈希({comboSM3DataFormat.SelectedItem}):";
        }

        private void ComboSM3HMACDataFormat_TabIndexChanged(object sender, EventArgs e)
        {
            //label7.Text = $"输入数据({comboSM3DataFormat.SelectedItem}):";
        }

        private void ComboSM3HMACOutputFormat_TabIndexChanged(object sender, EventArgs e)
        {
            //label7.Text = $"HMAC结果({comboSM3DataFormat.SelectedItem}):";
        }
    }
}