using CryptoTool.Common;
using CryptoTool.Common.GM;
using System.Text;
using Org.BouncyCastle.Crypto.Parameters;
using System.Collections.Generic;
using Newtonsoft.Json;

namespace CryptoTool.Win
{
    public partial class MedicareTabControl : UserControl
    {
        public event Action<string> StatusChanged;
        public event Action<string> SM4KeyGenerated;

        public MedicareTabControl()
        {
            InitializeComponent();
            InitializeDefaults();
        }

        private void InitializeDefaults()
        {
            // ��ʼ��ҽ��Ĭ��ֵ
            textMedicareAppId.Text = "43AF047BBA47FC8A1AE8EFB2XXXXXXXX";
            textMedicareAppSecret.Text = "4117E877F5FA0A0188891283E4B617D5";
            textMedicareEncType.Text = "SM4";
            textMedicareSignType.Text = "SM2";
            textMedicareVersion.Text = "2.0.1";

            // ����Ĭ�ϵ�ҵ������ʾ��
            var defaultData = new
            {
                appId = "43AF047BBA47FC8A1AE8EFB2XXXXXXXX",
                appUserId = "o8z4C5avQXqC0aWFPf1Mzu6D7xxxx",
                idNo = "350582xxxxxxxx3519",
                idType = "01",
                phoneNumber = "137xxxxx033",
                userName = "����"
            };
            textMedicareData.Text = JsonConvert.SerializeObject(defaultData, Formatting.Indented);

            // ���õ�ǰʱ���
            textMedicareTimestamp.Text = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString();
        }

        private void SetStatus(string message)
        {
            StatusChanged?.Invoke(message);
        }

        #region ҽ������

        private void btnGenerateMedicareKey_Click(object sender, EventArgs e)
        {
            try
            {
                SetStatus("��������ҽ��SM2��Կ��...");

                var keyPair = SM2Util.GenerateKeyPair();
                var publicKey = (ECPublicKeyParameters)keyPair.Public;
                var privateKey = (ECPrivateKeyParameters)keyPair.Private;

                textMedicarePublicKey.Text = SM2Util.PublicKeyToHex(publicKey);
                textMedicarePrivateKey.Text = SM2Util.PrivateKeyToHex(privateKey);

                SetStatus("ҽ��SM2��Կ���������");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"����ҽ��SM2��Կ��ʧ�ܣ�{ex.Message}", "����", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("����ҽ��SM2��Կ��ʧ��");
            }
        }

        private void btnImportMedicareKey_Click(object sender, EventArgs e)
        {
            try
            {
                using (OpenFileDialog openFileDialog = new OpenFileDialog())
                {
                    openFileDialog.Filter = "��Կ�ļ� (*.txt;*.key)|*.txt;*.key|�����ļ� (*.*)|*.*";
                    openFileDialog.Title = "����ҽ����Կ�ļ�";

                    if (openFileDialog.ShowDialog() == DialogResult.OK)
                    {
                        string content = File.ReadAllText(openFileDialog.FileName, Encoding.UTF8);
                        string[] lines = content.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);

                        if (lines.Length >= 2)
                        {
                            textMedicarePublicKey.Text = lines[0].Trim();
                            textMedicarePrivateKey.Text = lines[1].Trim();
                            SetStatus("ҽ����Կ����ɹ�");
                        }
                        else
                        {
                            MessageBox.Show("��Կ�ļ���ʽ����Ӧ������Կ��˽Կ���С�", "����", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"����ҽ����Կʧ�ܣ�{ex.Message}", "����", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("����ҽ����Կʧ��");
            }
        }

        private void btnExportMedicareKey_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textMedicarePublicKey.Text) || string.IsNullOrEmpty(textMedicarePrivateKey.Text))
                {
                    MessageBox.Show("�������ɻ�����ҽ����Կ�ԣ�", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                using (SaveFileDialog saveFileDialog = new SaveFileDialog())
                {
                    saveFileDialog.Filter = "��Կ�ļ� (*.txt)|*.txt|�����ļ� (*.*)|*.*";
                    saveFileDialog.Title = "����ҽ����Կ�ļ�";
                    saveFileDialog.FileName = "medicare_keys.txt";

                    if (saveFileDialog.ShowDialog() == DialogResult.OK)
                    {
                        string content = $"��Կ��\r\n{textMedicarePublicKey.Text}\r\n\r\n˽Կ��\r\n{textMedicarePrivateKey.Text}";
                        File.WriteAllText(saveFileDialog.FileName, content, Encoding.UTF8);
                        SetStatus("ҽ����Կ�����ɹ�");
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"����ҽ����Կʧ�ܣ�{ex.Message}", "����", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("����ҽ����Կʧ��");
            }
        }

        private void btnMedicareSign_Click(object sender, EventArgs e)
        {
            try
            {
                if (ValidateMedicareInputs(false))
                {
                    SetStatus("���ڽ���ҽ��ǩ��...");

                    // �����������
                    var parameters = BuildMedicareParameters();

                    // ����˽Կ
                    var privateKey = SM2Util.ParsePrivateKeyFromHex(textMedicarePrivateKey.Text);
                    string appSecret = textMedicareAppSecret.Text.Trim();

                    // ����ǩ���ַ���
                    string signatureString = MedicareUtil.BuildSignatureBaseString(parameters, appSecret);
                    textMedicareSignatureString.Text = signatureString;

                    // ����ǩ��
                    string signData = MedicareUtil.SignParameters(parameters, privateKey, appSecret);
                    textMedicareSignData.Text = signData;

                    SetStatus("ҽ��ǩ�����");
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"ҽ��ǩ��ʧ�ܣ�{ex.Message}", "����", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("ҽ��ǩ��ʧ��");
            }
        }

        private void btnMedicareVerify_Click(object sender, EventArgs e)
        {
            try
            {
                if (ValidateMedicareInputs(true))
                {
                    SetStatus("���ڽ���ҽ����ǩ...");

                    // ���������������signData������ǩ��
                    var parameters = BuildMedicareParameters();

                    // ������Կ
                    var publicKey = SM2Util.ParsePublicKeyFromHex(textMedicarePublicKey.Text);
                    string appSecret = textMedicareAppSecret.Text.Trim();
                    string signData = textMedicareSignData.Text.Trim();

                    // ��ǩ
                    bool verifyResult = MedicareUtil.VerifyParametersSignature(parameters, signData, publicKey, appSecret);

                    MessageBox.Show($"��ǩ�����{(verifyResult ? "��֤�ɹ�" : "��֤ʧ��")}",
                        "��ǩ���", MessageBoxButtons.OK,
                        verifyResult ? MessageBoxIcon.Information : MessageBoxIcon.Warning);

                    SetStatus($"ҽ����ǩ��� - {(verifyResult ? "��֤�ɹ�" : "��֤ʧ��")}");
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"ҽ����ǩʧ�ܣ�{ex.Message}", "����", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("ҽ����ǩʧ��");
            }
        }

        private void btnMedicareEncrypt_Click(object sender, EventArgs e)
        {
            try
            {
                if (ValidateMedicareEncryptedInputs(false))
                {
                    SetStatus("���ڽ���ҽ�����ݼ���...");

                    string appId = textMedicareAppId.Text.Trim();
                    string appSecret = textMedicareAppSecret.Text.Trim();

                    // ����JSON����
                    object dataObject;
                    try
                    {
                        dataObject = JsonConvert.DeserializeObject(textMedicareData.Text);
                    }
                    catch (JsonException)
                    {
                        // ���������ЧJSON��ʹ��ԭʼ�ַ���
                        dataObject = textMedicareData.Text;
                    }

                    // ��������
                    string encData = MedicareUtil.EncryptData(dataObject, appId, appSecret);
                    textMedicareEncData.Text = encData;

                    SetStatus("ҽ�����ݼ������");
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"ҽ�����ݼ���ʧ�ܣ�{ex.Message}", "����", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("ҽ�����ݼ���ʧ��");
            }
        }

        private void btnMedicareDecrypt_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(textMedicareEncData.Text))
                {
                    MessageBox.Show("������Ҫ���ܵ�encData��", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (string.IsNullOrWhiteSpace(textMedicareAppId.Text) || string.IsNullOrWhiteSpace(textMedicareAppSecret.Text))
                {
                    MessageBox.Show("������AppId��AppSecret��", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("���ڽ���ҽ�����ݽ���...");

                string appId = textMedicareAppId.Text.Trim();
                string appSecret = textMedicareAppSecret.Text.Trim();
                string encData = textMedicareEncData.Text.Trim();

                // ��������
                string decryptedData = MedicareUtil.DecryptEncData(encData, appId, appSecret);

                // ���Ը�ʽ��JSON��ʾ
                try
                {
                    var jsonObject = JsonConvert.DeserializeObject(decryptedData);
                    textMedicareDecData.Text = JsonConvert.SerializeObject(jsonObject, Formatting.Indented);
                }
                catch
                {
                    // ���������ЧJSON��ֱ����ʾԭʼ����
                    textMedicareDecData.Text = decryptedData;
                }

                SetStatus("ҽ�����ݽ������");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"ҽ�����ݽ���ʧ�ܣ�{ex.Message}", "����", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("ҽ�����ݽ���ʧ��");
            }
        }

        /// <summary>
        /// ҽ�����ܹ�������У��
        /// </summary>
        /// <param name="includeSignData"></param>
        /// <returns></returns>
        private bool ValidateMedicareEncryptedInputs(bool includeSignData)
        {
            if (string.IsNullOrWhiteSpace(textMedicareAppId.Text))
            {
                MessageBox.Show("������AppId��", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return false;
            }

            if (string.IsNullOrWhiteSpace(textMedicareAppSecret.Text))
            {
                MessageBox.Show("������AppSecret��", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return false;
            }

            if (string.IsNullOrWhiteSpace(textMedicareData.Text))
            {
                MessageBox.Show("������ҵ�����ݣ�", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return false;
            }

            return true;
        }

        /// <summary>
        /// ҽ��ǩ����ǩ��������У��
        /// </summary>
        /// <param name="includeSignData"></param>
        /// <returns></returns>
        private bool ValidateMedicareInputs(bool includeSignData)
        {
            if (string.IsNullOrWhiteSpace(textMedicareAppId.Text))
            {
                MessageBox.Show("������AppId��", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return false;
            }

            if (string.IsNullOrWhiteSpace(textMedicareAppSecret.Text))
            {
                MessageBox.Show("������AppSecret��", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return false;
            }

            if (string.IsNullOrWhiteSpace(textMedicareTimestamp.Text))
            {
                MessageBox.Show("������ʱ�����", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return false;
            }

            if (string.IsNullOrWhiteSpace(textMedicarePublicKey.Text))
            {
                MessageBox.Show("�������ɻ����빫Կ��", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return false;
            }

            if (string.IsNullOrWhiteSpace(textMedicarePrivateKey.Text))
            {
                MessageBox.Show("�������ɻ�����˽Կ��", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return false;
            }

            if (includeSignData && string.IsNullOrWhiteSpace(textMedicareSignData.Text))
            {
                MessageBox.Show("���Ƚ���ǩ��������ȡSignData��", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return false;
            }

            return true;
        }

        private Dictionary<string, object> BuildMedicareParameters()
        {
            var parameters = new Dictionary<string, object>();

            parameters["appId"] = textMedicareAppId.Text.Trim();
            parameters["encType"] = textMedicareEncType.Text.Trim();
            parameters["signType"] = textMedicareSignType.Text.Trim();
            parameters["timestamp"] = textMedicareTimestamp.Text.Trim();
            parameters["version"] = textMedicareVersion.Text.Trim();

            // ������������ݣ����data�ֶ�
            if (!string.IsNullOrWhiteSpace(textMedicareData.Text))
            {
                try
                {
                    // ���Խ���ΪJSON����
                    var dataObject = JsonConvert.DeserializeObject(textMedicareData.Text);
                    parameters["data"] = dataObject;
                }
                catch (JsonException)
                {
                    // ���������ЧJSON��ʹ��ԭʼ�ַ���
                    parameters["data"] = textMedicareData.Text.Trim();
                }
            }

            return parameters;
        }

        #endregion

        #region ҽ��SM4��Կ���ɹ���

        private void btnGenerateMedicareSM4Key_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(textMedicareAppId.Text))
                {
                    MessageBox.Show("������ҽ��AppId��", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (string.IsNullOrWhiteSpace(textMedicareAppSecret.Text))
                {
                    MessageBox.Show("������ҽ��AppSecret��", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                string appId = textMedicareAppId.Text.Trim();
                string appSecret = textMedicareAppSecret.Text.Trim();

                if (appId.Length < 16)
                {
                    MessageBox.Show("AppId���Ȳ���16�ֽڣ��޷�����SM4��Կ��", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("���ڸ���ҽ��AppId��AppSecret����SM4��Կ...");

                // ʹ��MedicareUtil�е��߼�����SM4��Կ
                string derivedKey = GetMedicareSM4Key(appId, appSecret);
                textMedicareSM4Key.Text = derivedKey;

                // ֪ͨ�ⲿ����SM4��Կ
                SM4KeyGenerated?.Invoke(derivedKey);

                SetStatus($"ҽ��SM4��Կ������� - ����AppId��AppSecret����");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"����ҽ��SM4��Կʧ�ܣ�{ex.Message}", "����", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("����ҽ��SM4��Կʧ��");
            }
        }

        /// <summary>
        /// ����ҽ���淶����AppId��AppSecret����SM4��Կ
        /// </summary>
        /// <param name="appId"></param>
        /// <param name="appSecret"></param>
        /// <returns></returns>
        private string GetMedicareSM4Key(string appId, string appSecret)
        {
            // ʵ��ҽ���淶��SM4��Կ�����㷨
            // ��appId(����id)��ΪKey����appSecret���ܣ��õ�����Կ����ȡǰ16�ֽ���ΪSM4��Կ

            if (appId.Length < 16)
            {
                throw new ArgumentException("appId���Ȳ���16�ֽڣ��޷�����SM4��Կ", nameof(appId));
            }

            // ȡappId��ǰ16�ֽ���ΪSM4��Կ������appSecret
            string keyString = appId.Substring(0, 16);

            // ʹ��SM4-ECBģʽ��appIdǰ16�ַ���Ϊ��Կ����appSecret���м���
            string encryptedData = SM4Util.EncryptEcb(appSecret, keyString, Encoding.UTF8);

            // ��Base64���ת��Ϊ�ֽ����飬��ת��ΪHex�ַ�����ȡǰ16���ַ���8�ֽڣ���Ϊ���յ�SM4��Կ
            byte[] encryptedBytes = Convert.FromBase64String(encryptedData);
            string hexResult = SM4Util.BytesToHex(encryptedBytes);

            // ȡǰ16���ַ���Ϊ���յ�SM4��Կ��Hex��ʽ��ʵ�ʶ�Ӧ8�ֽڣ�
            // ��SM4��Ҫ16�ֽ���Կ������ȡǰ32���ַ�����Ӧ16�ֽڣ�
            string finalKey = hexResult.Substring(0, Math.Min(32, hexResult.Length));

            return finalKey;
        }

        #endregion

        /// <summary>
        /// ��ʱ����ı���ʧȥ������δ�������ʱ���Զ�����Ϊ��ǰʱ���
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void TextMedicareTimestamp_Leave(object sender, EventArgs e)
        {
            if (string.IsNullOrWhiteSpace(textMedicareTimestamp.Text))
            {
                long timeStamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                textMedicareTimestamp.Text = timeStamp.ToString();
            }
        }
    }
}