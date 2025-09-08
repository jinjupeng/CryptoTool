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
            // ����Ĭ��ѡ��
            comboSM3DataFormat.SelectedIndex = 0; // Text
            comboSM3OutputFormat.SelectedIndex = 0; // Hex
            comboSM3FileHashFormat.SelectedIndex = 0; // Hex
            comboSM3VerifyDataFormat.SelectedIndex = 0; // Text
            comboSM3VerifyHashFormat.SelectedIndex = 0; // Hex
            comboSM3HMACDataFormat.SelectedIndex = 0; // Text
            comboSM3HMACOutputFormat.SelectedIndex = 0; // Hex

            // ����ʾ������
            textSM3Input.Text = "Hello SM3!";
            textSM3HMACData.Text = "Hello HMAC-SM3!";
            textSM3HMACKey.Text = "mySecretKey";
        }

        private void SetStatus(string message)
        {
            StatusChanged?.Invoke(message);
        }

        #region SM3��ϣ����

        private void btnSM3Hash_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textSM3Input.Text))
                {
                    MessageBox.Show("������Ҫ�����ϣ�����ݣ�", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("���ڼ���SM3��ϣ...");

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
                SetStatus($"SM3��ϣ������� - �����ʽ��{dataFormat}�������ʽ��{outputFormat}");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"SM3��ϣ����ʧ�ܣ�{ex.Message}", "����", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("SM3��ϣ����ʧ��");
            }
        }

        private void btnSM3Clear_Click(object sender, EventArgs e)
        {
            textSM3Input.Clear();
            textSM3Output.Clear();
            SetStatus("�������������");
        }

        #endregion

        #region �ļ���ϣ����

        private void btnSM3SelectFile_Click(object sender, EventArgs e)
        {
            try
            {
                using (OpenFileDialog openFileDialog = new OpenFileDialog())
                {
                    openFileDialog.Title = "ѡ��Ҫ����SM3��ϣ���ļ�";
                    openFileDialog.Filter = "�����ļ� (*.*)|*.*";

                    if (openFileDialog.ShowDialog() == DialogResult.OK)
                    {
                        textSM3FilePath.Text = openFileDialog.FileName;
                        SetStatus("��ѡ���ļ���" + Path.GetFileName(openFileDialog.FileName));
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"ѡ���ļ�ʧ�ܣ�{ex.Message}", "����", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("ѡ���ļ�ʧ��");
            }
        }

        private void btnSM3ComputeFileHash_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textSM3FilePath.Text))
                {
                    MessageBox.Show("����ѡ��Ҫ�����ϣ���ļ���", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (!File.Exists(textSM3FilePath.Text))
                {
                    MessageBox.Show("�ļ������ڣ�������ѡ��", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("���ڼ����ļ�SM3��ϣ...");

                string outputFormat = comboSM3FileHashFormat.SelectedItem.ToString();
                
                string result = outputFormat switch
                {
                    "Hex" => SM3Util.ComputeFileHashHex(textSM3FilePath.Text),
                    "Base64" => SM3Util.ComputeFileHashBase64(textSM3FilePath.Text),
                    _ => SM3Util.ComputeFileHashHex(textSM3FilePath.Text)
                };

                textSM3FileHash.Text = result;
                
                FileInfo fileInfo = new FileInfo(textSM3FilePath.Text);
                SetStatus($"�ļ�SM3��ϣ������� - �ļ���С��{FormatFileSize(fileInfo.Length)}�������ʽ��{outputFormat}");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"�����ļ���ϣʧ�ܣ�{ex.Message}", "����", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("�����ļ���ϣʧ��");
            }
        }

        #endregion

        #region ��ϣֵ��֤

        private void btnSM3Verify_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textSM3VerifyData.Text))
                {
                    MessageBox.Show("������Ҫ��֤��ԭʼ���ݣ�", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (string.IsNullOrEmpty(textSM3VerifyHash.Text))
                {
                    MessageBox.Show("�����������Ĺ�ϣֵ��", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("������֤SM3��ϣֵ...");

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

                labelSM3VerifyResult.Text = $"��֤���: {(verifyResult ? "��֤�ɹ�" : "��֤ʧ��")}";
                labelSM3VerifyResult.ForeColor = verifyResult ? Color.Green : Color.Red;

                SetStatus($"SM3��ϣ��֤��� - {(verifyResult ? "��֤�ɹ�" : "��֤ʧ��")}");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"��ϣֵ��֤ʧ�ܣ�{ex.Message}", "����", MessageBoxButtons.OK, MessageBoxIcon.Error);
                labelSM3VerifyResult.Text = "��֤���: ��֤�쳣";
                labelSM3VerifyResult.ForeColor = Color.Red;
                SetStatus("��ϣֵ��֤ʧ��");
            }
        }

        #endregion

        #region HMAC-SM3����

        private void btnSM3HMAC_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textSM3HMACData.Text))
                {
                    MessageBox.Show("������Ҫ����HMAC�����ݣ�", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (string.IsNullOrEmpty(textSM3HMACKey.Text))
                {
                    MessageBox.Show("������HMAC��Կ��", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("���ڼ���HMAC-SM3...");

                string inputData = textSM3HMACData.Text;
                string key = textSM3HMACKey.Text;
                string dataFormat = comboSM3HMACDataFormat.SelectedItem.ToString();
                string outputFormat = comboSM3HMACOutputFormat.SelectedItem.ToString();

                byte[] dataBytes = ConvertInputData(inputData, dataFormat);
                byte[] keyBytes = Encoding.UTF8.GetBytes(key); // HMAC��Կͨ��ʹ��UTF8����
                
                string result = outputFormat switch
                {
                    "Hex" => SM3Util.ComputeHMacHex(dataBytes, keyBytes),
                    "Base64" => SM3Util.ComputeHMacBase64(dataBytes, keyBytes),
                    _ => SM3Util.ComputeHMacHex(dataBytes, keyBytes)
                };

                textSM3HMACOutput.Text = result;
                SetStatus($"HMAC-SM3������� - ���ݸ�ʽ��{dataFormat}�������ʽ��{outputFormat}");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"HMAC-SM3����ʧ�ܣ�{ex.Message}", "����", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("HMAC-SM3����ʧ��");
            }
        }

        #endregion

        #region ��������

        /// <summary>
        /// ���ݸ�ʽת����������Ϊ�ֽ�����
        /// </summary>
        /// <param name="input">�����ַ���</param>
        /// <param name="format">���ݸ�ʽ</param>
        /// <returns>�ֽ�����</returns>
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
        /// ��ʽ���ļ���С��ʾ
        /// </summary>
        /// <param name="bytes">�ֽ���</param>
        /// <returns>��ʽ�����ļ���С�ַ���</returns>
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
            //label1.Text = $"��������({comboSM3DataFormat.SelectedItem}):";
        }
        private void ComboSM3OutputFormat_TabIndexChanged(object sender, EventArgs e)
        {
            //label2.Text = $"��ϣ���({comboSM3DataFormat.SelectedItem}):";
        }


        private void ComboSM3FileHashFormat_TabIndexChanged(object sender, EventArgs e)
        {
            //label4.Text = $"��ϣ���({comboSM3DataFormat.SelectedItem}):";
        }

        private void ComboSM3VerifyDataFormat_TabIndexChanged(object sender, EventArgs e)
        {
            //label5.Text = $"ԭʼ����({comboSM3DataFormat.SelectedItem}):";
        }
        private void ComboSM3VerifyHashFormat_TabIndexChanged(object sender, EventArgs e)
        {
            //label6.Text = $"������ϣ({comboSM3DataFormat.SelectedItem}):";
        }

        private void ComboSM3HMACDataFormat_TabIndexChanged(object sender, EventArgs e)
        {
            //label7.Text = $"��������({comboSM3DataFormat.SelectedItem}):";
        }

        private void ComboSM3HMACOutputFormat_TabIndexChanged(object sender, EventArgs e)
        {
            //label7.Text = $"HMAC���({comboSM3DataFormat.SelectedItem}):";
        }
    }
}