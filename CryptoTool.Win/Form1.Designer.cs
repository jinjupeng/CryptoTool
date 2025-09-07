namespace CryptoTool.Win
{
    partial class Form1
    {
        /// <summary>
        ///  Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        ///  Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        ///  Required method for Designer support - do not modify
        ///  the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            tabControl1 = new TabControl();
            tabRSA = new TabPage();
            groupBoxRSASign = new GroupBox();
            comboRSASignAlgmFormat = new ComboBox();
            label29 = new Label();
            comboRSASignOutputFormat = new ComboBox();
            label28 = new Label();
            labelRSAVerifyResult = new Label();
            label8 = new Label();
            textRSASignature = new TextBox();
            label7 = new Label();
            textRSASignData = new TextBox();
            btnRSAVerify = new Button();
            btnRSASign = new Button();
            groupBoxRSAEncrypt = new GroupBox();
            comboRSAEncryptOutputFormat = new ComboBox();
            label27 = new Label();
            label6 = new Label();
            textRSACipherText = new TextBox();
            comboRSAKeyPadding = new ComboBox();
            label5 = new Label();
            label25 = new Label();
            textRSAPlainText = new TextBox();
            btnRSADecrypt = new Button();
            btnRSAEncrypt = new Button();
            groupBoxRSAKeys = new GroupBox();
            comboRSAKeyOutputFormat = new ComboBox();
            label26 = new Label();
            btnExportRSAKey = new Button();
            btnImportRSAKey = new Button();
            label4 = new Label();
            textRSAPrivateKey = new TextBox();
            label3 = new Label();
            textRSAPublicKey = new TextBox();
            label2 = new Label();
            comboRSAKeyFormat = new ComboBox();
            label1 = new Label();
            comboRSAKeySize = new ComboBox();
            btnGenerateRSAKey = new Button();
            tabSM4 = new TabPage();
            groupBoxSM4Encrypt = new GroupBox();
            labelSM4CiphertextFormat = new Label();
            comboSM4CiphertextFormat = new ComboBox();
            labelSM4PlaintextFormat = new Label();
            comboSM4PlaintextFormat = new ComboBox();
            label15 = new Label();
            comboSM4Padding = new ComboBox();
            label14 = new Label();
            comboSM4Mode = new ComboBox();
            label13 = new Label();
            textSM4CipherText = new TextBox();
            label12 = new Label();
            textSM4PlainText = new TextBox();
            btnSM4Decrypt = new Button();
            btnSM4Encrypt = new Button();
            groupBoxSM4Keys = new GroupBox();
            labelSM4IVFormat = new Label();
            comboSM4IVFormat = new ComboBox();
            labelSM4KeyFormat = new Label();
            comboSM4KeyFormat = new ComboBox();
            label11 = new Label();
            textSM4IV = new TextBox();
            label10 = new Label();
            textSM4Key = new TextBox();
            btnGenerateSM4IV = new Button();
            btnGenerateSM4Key = new Button();
            tabSM2 = new TabPage();
            groupBoxSM2Sign = new GroupBox();
            labelSM2VerifyResult = new Label();
            label24 = new Label();
            textSM2Signature = new TextBox();
            label23 = new Label();
            textSM2SignData = new TextBox();
            btnSM2Verify = new Button();
            btnSM2Sign = new Button();
            label22 = new Label();
            comboSM2SignFormat = new ComboBox();
            groupBoxSM2Encrypt = new GroupBox();
            label21 = new Label();
            textSM2CipherText = new TextBox();
            label20 = new Label();
            textSM2PlainText = new TextBox();
            btnSM2Decrypt = new Button();
            btnSM2Encrypt = new Button();
            label19 = new Label();
            comboSM2CipherFormat = new ComboBox();
            groupBoxSM2Keys = new GroupBox();
            btnExportSM2Key = new Button();
            btnImportSM2Key = new Button();
            label18 = new Label();
            textSM2PrivateKey = new TextBox();
            label17 = new Label();
            textSM2PublicKey = new TextBox();
            label16 = new Label();
            comboSM2KeyFormat = new ComboBox();
            btnGenerateSM2Key = new Button();
            tabMedicare = new TabPage();
            groupBoxMedicareParams = new GroupBox();
            labelMedicareAppId = new Label();
            textMedicareAppId = new TextBox();
            labelMedicareAppSecret = new Label();
            textMedicareAppSecret = new TextBox();
            labelMedicareVersion = new Label();
            textMedicareVersion = new TextBox();
            labelMedicareTimestamp = new Label();
            textMedicareTimestamp = new TextBox();
            labelMedicareSignType = new Label();
            textMedicareSignType = new TextBox();
            labelMedicareEncType = new Label();
            textMedicareEncType = new TextBox();
            labelMedicareData = new Label();
            textMedicareData = new TextBox();
            groupBoxMedicareKeys = new GroupBox();
            btnGenerateMedicareSM4Key = new Button();
            labelMedicareSM4Key = new Label();
            textMedicareSM4Key = new TextBox();
            btnGenerateMedicareKey = new Button();
            btnImportMedicareKey = new Button();
            btnExportMedicareKey = new Button();
            labelMedicarePublicKey = new Label();
            textMedicarePublicKey = new TextBox();
            labelMedicarePrivateKey = new Label();
            textMedicarePrivateKey = new TextBox();
            groupBoxMedicareAction = new GroupBox();
            btnMedicareSign = new Button();
            btnMedicareVerify = new Button();
            btnMedicareEncrypt = new Button();
            btnMedicareDecrypt = new Button();
            labelMedicareSignatureString = new Label();
            textMedicareSignatureString = new TextBox();
            labelMedicareSignData = new Label();
            textMedicareSignData = new TextBox();
            labelMedicareEncData = new Label();
            textMedicareEncData = new TextBox();
            labelMedicareDecData = new Label();
            textMedicareDecData = new TextBox();
            statusStrip1 = new StatusStrip();
            toolStripStatusLabel1 = new ToolStripStatusLabel();
            tabControl1.SuspendLayout();
            tabRSA.SuspendLayout();
            groupBoxRSASign.SuspendLayout();
            groupBoxRSAEncrypt.SuspendLayout();
            groupBoxRSAKeys.SuspendLayout();
            tabSM4.SuspendLayout();
            groupBoxSM4Encrypt.SuspendLayout();
            groupBoxSM4Keys.SuspendLayout();
            tabSM2.SuspendLayout();
            groupBoxSM2Sign.SuspendLayout();
            groupBoxSM2Encrypt.SuspendLayout();
            groupBoxSM2Keys.SuspendLayout();
            tabMedicare.SuspendLayout();
            groupBoxMedicareParams.SuspendLayout();
            groupBoxMedicareKeys.SuspendLayout();
            groupBoxMedicareAction.SuspendLayout();
            statusStrip1.SuspendLayout();
            SuspendLayout();
            // 
            // tabControl1
            // 
            tabControl1.Controls.Add(tabRSA);
            tabControl1.Controls.Add(tabSM4);
            tabControl1.Controls.Add(tabSM2);
            tabControl1.Controls.Add(tabMedicare);
            tabControl1.Dock = DockStyle.Fill;
            tabControl1.Location = new Point(0, 0);
            tabControl1.Margin = new Padding(4);
            tabControl1.Name = "tabControl1";
            tabControl1.SelectedIndex = 0;
            tabControl1.Size = new Size(1286, 1055);
            tabControl1.TabIndex = 0;
            // 
            // tabRSA
            // 
            tabRSA.Controls.Add(groupBoxRSASign);
            tabRSA.Controls.Add(groupBoxRSAEncrypt);
            tabRSA.Controls.Add(groupBoxRSAKeys);
            tabRSA.Location = new Point(4, 29);
            tabRSA.Margin = new Padding(4);
            tabRSA.Name = "tabRSA";
            tabRSA.Padding = new Padding(4);
            tabRSA.Size = new Size(1278, 1022);
            tabRSA.TabIndex = 0;
            tabRSA.Text = "RSA算法";
            tabRSA.UseVisualStyleBackColor = true;
            // 
            // groupBoxRSASign
            // 
            groupBoxRSASign.Controls.Add(comboRSASignAlgmFormat);
            groupBoxRSASign.Controls.Add(label29);
            groupBoxRSASign.Controls.Add(comboRSASignOutputFormat);
            groupBoxRSASign.Controls.Add(label28);
            groupBoxRSASign.Controls.Add(labelRSAVerifyResult);
            groupBoxRSASign.Controls.Add(label8);
            groupBoxRSASign.Controls.Add(textRSASignature);
            groupBoxRSASign.Controls.Add(label7);
            groupBoxRSASign.Controls.Add(textRSASignData);
            groupBoxRSASign.Controls.Add(btnRSAVerify);
            groupBoxRSASign.Controls.Add(btnRSASign);
            groupBoxRSASign.Location = new Point(4, 564);
            groupBoxRSASign.Margin = new Padding(4);
            groupBoxRSASign.Name = "groupBoxRSASign";
            groupBoxRSASign.Padding = new Padding(4);
            groupBoxRSASign.Size = new Size(1260, 256);
            groupBoxRSASign.TabIndex = 2;
            groupBoxRSASign.TabStop = false;
            groupBoxRSASign.Text = "RSA数字签名";
            // 
            // comboRSASignAlgmFormat
            // 
            comboRSASignAlgmFormat.DropDownStyle = ComboBoxStyle.DropDownList;
            comboRSASignAlgmFormat.FormattingEnabled = true;
            comboRSASignAlgmFormat.Items.AddRange(new object[] { "SHA1withRSA(RSA1)", "SHA256withRSA(RSA2)", "SHA384withRSA", "SHA512withRSA", "MD5withRSA" });
            comboRSASignAlgmFormat.Location = new Point(235, 31);
            comboRSASignAlgmFormat.Margin = new Padding(4);
            comboRSASignAlgmFormat.Name = "comboRSASignAlgmFormat";
            comboRSASignAlgmFormat.Size = new Size(203, 28);
            comboRSASignAlgmFormat.TabIndex = 18;
            // 
            // label29
            // 
            label29.AutoSize = true;
            label29.Location = new Point(151, 34);
            label29.Margin = new Padding(4, 0, 4, 0);
            label29.Name = "label29";
            label29.Size = new Size(73, 20);
            label29.TabIndex = 17;
            label29.Text = "签名算法:";
            // 
            // comboRSASignOutputFormat
            // 
            comboRSASignOutputFormat.DropDownStyle = ComboBoxStyle.DropDownList;
            comboRSASignOutputFormat.FormattingEnabled = true;
            comboRSASignOutputFormat.Items.AddRange(new object[] { "Base64", "Hex" });
            comboRSASignOutputFormat.Location = new Point(606, 30);
            comboRSASignOutputFormat.Margin = new Padding(4);
            comboRSASignOutputFormat.Name = "comboRSASignOutputFormat";
            comboRSASignOutputFormat.Size = new Size(173, 28);
            comboRSASignOutputFormat.TabIndex = 16;
            comboRSASignOutputFormat.SelectedIndexChanged += ComboRSASignOutputFormat_SelectedIndexChanged;
            // 
            // label28
            // 
            label28.AutoSize = true;
            label28.Location = new Point(466, 34);
            label28.Margin = new Padding(4, 0, 4, 0);
            label28.Name = "label28";
            label28.Size = new Size(73, 20);
            label28.TabIndex = 15;
            label28.Text = "签名格式:";
            // 
            // labelRSAVerifyResult
            // 
            labelRSAVerifyResult.AutoSize = true;
            labelRSAVerifyResult.Location = new Point(514, 214);
            labelRSAVerifyResult.Margin = new Padding(4, 0, 4, 0);
            labelRSAVerifyResult.Name = "labelRSAVerifyResult";
            labelRSAVerifyResult.Size = new Size(73, 20);
            labelRSAVerifyResult.TabIndex = 8;
            labelRSAVerifyResult.Text = "验签结果:";
            // 
            // label8
            // 
            label8.AutoSize = true;
            label8.Location = new Point(19, 145);
            label8.Margin = new Padding(4, 0, 4, 0);
            label8.Name = "label8";
            label8.Size = new Size(43, 20);
            label8.TabIndex = 5;
            label8.Text = "签名:";
            // 
            // textRSASignature
            // 
            textRSASignature.Location = new Point(151, 141);
            textRSASignature.Margin = new Padding(4);
            textRSASignature.Multiline = true;
            textRSASignature.Name = "textRSASignature";
            textRSASignature.ScrollBars = ScrollBars.Both;
            textRSASignature.Size = new Size(1089, 58);
            textRSASignature.TabIndex = 4;
            // 
            // label7
            // 
            label7.AutoSize = true;
            label7.Location = new Point(19, 74);
            label7.Margin = new Padding(4, 0, 4, 0);
            label7.Name = "label7";
            label7.Size = new Size(73, 20);
            label7.TabIndex = 3;
            label7.Text = "原文数据:";
            // 
            // textRSASignData
            // 
            textRSASignData.Location = new Point(151, 71);
            textRSASignData.Margin = new Padding(4);
            textRSASignData.Multiline = true;
            textRSASignData.Name = "textRSASignData";
            textRSASignData.ScrollBars = ScrollBars.Both;
            textRSASignData.Size = new Size(1089, 58);
            textRSASignData.TabIndex = 2;
            // 
            // btnRSAVerify
            // 
            btnRSAVerify.Location = new Point(1054, 28);
            btnRSAVerify.Margin = new Padding(4);
            btnRSAVerify.Name = "btnRSAVerify";
            btnRSAVerify.Size = new Size(103, 31);
            btnRSAVerify.TabIndex = 1;
            btnRSAVerify.Text = "验签";
            btnRSAVerify.UseVisualStyleBackColor = true;
            btnRSAVerify.Click += btnRSAVerify_Click;
            // 
            // btnRSASign
            // 
            btnRSASign.Location = new Point(865, 29);
            btnRSASign.Margin = new Padding(4);
            btnRSASign.Name = "btnRSASign";
            btnRSASign.Size = new Size(103, 30);
            btnRSASign.TabIndex = 0;
            btnRSASign.Text = "签名";
            btnRSASign.UseVisualStyleBackColor = true;
            btnRSASign.Click += btnRSASign_Click;
            // 
            // groupBoxRSAEncrypt
            // 
            groupBoxRSAEncrypt.Controls.Add(comboRSAEncryptOutputFormat);
            groupBoxRSAEncrypt.Controls.Add(label27);
            groupBoxRSAEncrypt.Controls.Add(label6);
            groupBoxRSAEncrypt.Controls.Add(textRSACipherText);
            groupBoxRSAEncrypt.Controls.Add(comboRSAKeyPadding);
            groupBoxRSAEncrypt.Controls.Add(label5);
            groupBoxRSAEncrypt.Controls.Add(label25);
            groupBoxRSAEncrypt.Controls.Add(textRSAPlainText);
            groupBoxRSAEncrypt.Controls.Add(btnRSADecrypt);
            groupBoxRSAEncrypt.Controls.Add(btnRSAEncrypt);
            groupBoxRSAEncrypt.Location = new Point(4, 324);
            groupBoxRSAEncrypt.Margin = new Padding(4);
            groupBoxRSAEncrypt.Name = "groupBoxRSAEncrypt";
            groupBoxRSAEncrypt.Padding = new Padding(4);
            groupBoxRSAEncrypt.Size = new Size(1260, 212);
            groupBoxRSAEncrypt.TabIndex = 1;
            groupBoxRSAEncrypt.TabStop = false;
            groupBoxRSAEncrypt.Text = "RSA加密解密";
            // 
            // comboRSAEncryptOutputFormat
            // 
            comboRSAEncryptOutputFormat.DropDownStyle = ComboBoxStyle.DropDownList;
            comboRSAEncryptOutputFormat.FormattingEnabled = true;
            comboRSAEncryptOutputFormat.Items.AddRange(new object[] { "Base64", "Hex" });
            comboRSAEncryptOutputFormat.Location = new Point(596, 32);
            comboRSAEncryptOutputFormat.Margin = new Padding(4);
            comboRSAEncryptOutputFormat.Name = "comboRSAEncryptOutputFormat";
            comboRSAEncryptOutputFormat.Size = new Size(173, 28);
            comboRSAEncryptOutputFormat.TabIndex = 15;
            comboRSAEncryptOutputFormat.SelectedIndexChanged += ComboRSAEncryptOutputFormat_SelectedIndexChanged;
            // 
            // label27
            // 
            label27.AutoSize = true;
            label27.Location = new Point(466, 35);
            label27.Margin = new Padding(4, 0, 4, 0);
            label27.Name = "label27";
            label27.Size = new Size(73, 20);
            label27.TabIndex = 14;
            label27.Text = "密文格式:";
            // 
            // label6
            // 
            label6.AutoSize = true;
            label6.Location = new Point(19, 149);
            label6.Margin = new Padding(4, 0, 4, 0);
            label6.Name = "label6";
            label6.Size = new Size(43, 20);
            label6.TabIndex = 5;
            label6.Text = "密文:";
            // 
            // textRSACipherText
            // 
            textRSACipherText.Location = new Point(151, 146);
            textRSACipherText.Margin = new Padding(4);
            textRSACipherText.Multiline = true;
            textRSACipherText.Name = "textRSACipherText";
            textRSACipherText.ScrollBars = ScrollBars.Both;
            textRSACipherText.Size = new Size(1089, 58);
            textRSACipherText.TabIndex = 4;
            // 
            // comboRSAKeyPadding
            // 
            comboRSAKeyPadding.DropDownStyle = ComboBoxStyle.DropDownList;
            comboRSAKeyPadding.FormattingEnabled = true;
            comboRSAKeyPadding.Items.AddRange(new object[] { "PKCS1", "OAEP", "NoPadding" });
            comboRSAKeyPadding.Location = new Point(235, 32);
            comboRSAKeyPadding.Margin = new Padding(4);
            comboRSAKeyPadding.Name = "comboRSAKeyPadding";
            comboRSAKeyPadding.Size = new Size(173, 28);
            comboRSAKeyPadding.TabIndex = 12;
            // 
            // label5
            // 
            label5.AutoSize = true;
            label5.Location = new Point(19, 80);
            label5.Margin = new Padding(4, 0, 4, 0);
            label5.Name = "label5";
            label5.Size = new Size(43, 20);
            label5.TabIndex = 3;
            label5.Text = "明文:";
            // 
            // label25
            // 
            label25.AutoSize = true;
            label25.Location = new Point(151, 35);
            label25.Margin = new Padding(4, 0, 4, 0);
            label25.Name = "label25";
            label25.Size = new Size(73, 20);
            label25.TabIndex = 11;
            label25.Text = "填充方式:";
            // 
            // textRSAPlainText
            // 
            textRSAPlainText.Location = new Point(151, 80);
            textRSAPlainText.Margin = new Padding(4);
            textRSAPlainText.Multiline = true;
            textRSAPlainText.Name = "textRSAPlainText";
            textRSAPlainText.ScrollBars = ScrollBars.Both;
            textRSAPlainText.Size = new Size(1089, 58);
            textRSAPlainText.TabIndex = 2;
            // 
            // btnRSADecrypt
            // 
            btnRSADecrypt.Location = new Point(1036, 28);
            btnRSADecrypt.Margin = new Padding(4);
            btnRSADecrypt.Name = "btnRSADecrypt";
            btnRSADecrypt.Size = new Size(103, 35);
            btnRSADecrypt.TabIndex = 1;
            btnRSADecrypt.Text = "解密";
            btnRSADecrypt.UseVisualStyleBackColor = true;
            btnRSADecrypt.Click += btnRSADecrypt_Click;
            // 
            // btnRSAEncrypt
            // 
            btnRSAEncrypt.Location = new Point(856, 28);
            btnRSAEncrypt.Margin = new Padding(4);
            btnRSAEncrypt.Name = "btnRSAEncrypt";
            btnRSAEncrypt.Size = new Size(103, 35);
            btnRSAEncrypt.TabIndex = 0;
            btnRSAEncrypt.Text = "加密";
            btnRSAEncrypt.UseVisualStyleBackColor = true;
            btnRSAEncrypt.Click += btnRSAEncrypt_Click;
            // 
            // groupBoxRSAKeys
            // 
            groupBoxRSAKeys.Controls.Add(comboRSAKeyOutputFormat);
            groupBoxRSAKeys.Controls.Add(label26);
            groupBoxRSAKeys.Controls.Add(btnExportRSAKey);
            groupBoxRSAKeys.Controls.Add(btnImportRSAKey);
            groupBoxRSAKeys.Controls.Add(label4);
            groupBoxRSAKeys.Controls.Add(textRSAPrivateKey);
            groupBoxRSAKeys.Controls.Add(label3);
            groupBoxRSAKeys.Controls.Add(textRSAPublicKey);
            groupBoxRSAKeys.Controls.Add(label2);
            groupBoxRSAKeys.Controls.Add(comboRSAKeyFormat);
            groupBoxRSAKeys.Controls.Add(label1);
            groupBoxRSAKeys.Controls.Add(comboRSAKeySize);
            groupBoxRSAKeys.Controls.Add(btnGenerateRSAKey);
            groupBoxRSAKeys.Location = new Point(8, 7);
            groupBoxRSAKeys.Margin = new Padding(4);
            groupBoxRSAKeys.Name = "groupBoxRSAKeys";
            groupBoxRSAKeys.Padding = new Padding(4);
            groupBoxRSAKeys.Size = new Size(1260, 301);
            groupBoxRSAKeys.TabIndex = 0;
            groupBoxRSAKeys.TabStop = false;
            groupBoxRSAKeys.Text = "RSA密钥生成";
            // 
            // comboRSAKeyOutputFormat
            // 
            comboRSAKeyOutputFormat.DropDownStyle = ComboBoxStyle.DropDownList;
            comboRSAKeyOutputFormat.FormattingEnabled = true;
            comboRSAKeyOutputFormat.Items.AddRange(new object[] { "PEM", "Base64", "Hex" });
            comboRSAKeyOutputFormat.Location = new Point(793, 30);
            comboRSAKeyOutputFormat.Margin = new Padding(4);
            comboRSAKeyOutputFormat.Name = "comboRSAKeyOutputFormat";
            comboRSAKeyOutputFormat.Size = new Size(173, 28);
            comboRSAKeyOutputFormat.TabIndex = 14;
            comboRSAKeyOutputFormat.SelectedIndexChanged += ComboRSAKeyOutputFormat_SelectedIndexChanged;
            // 
            // label26
            // 
            label26.AutoSize = true;
            label26.Location = new Point(682, 33);
            label26.Margin = new Padding(4, 0, 4, 0);
            label26.Name = "label26";
            label26.Size = new Size(73, 20);
            label26.TabIndex = 13;
            label26.Text = "密钥格式:";
            // 
            // btnExportRSAKey
            // 
            btnExportRSAKey.Location = new Point(458, 80);
            btnExportRSAKey.Margin = new Padding(4);
            btnExportRSAKey.Name = "btnExportRSAKey";
            btnExportRSAKey.Size = new Size(103, 28);
            btnExportRSAKey.TabIndex = 10;
            btnExportRSAKey.Text = "导出密钥";
            btnExportRSAKey.UseVisualStyleBackColor = true;
            btnExportRSAKey.Click += btnExportRSAKey_Click;
            // 
            // btnImportRSAKey
            // 
            btnImportRSAKey.Location = new Point(311, 80);
            btnImportRSAKey.Margin = new Padding(4);
            btnImportRSAKey.Name = "btnImportRSAKey";
            btnImportRSAKey.Size = new Size(103, 28);
            btnImportRSAKey.TabIndex = 9;
            btnImportRSAKey.Text = "导入密钥";
            btnImportRSAKey.UseVisualStyleBackColor = true;
            btnImportRSAKey.Click += btnImportRSAKey_Click;
            // 
            // label4
            // 
            label4.AutoSize = true;
            label4.Location = new Point(15, 223);
            label4.Margin = new Padding(4, 0, 4, 0);
            label4.Name = "label4";
            label4.Size = new Size(43, 20);
            label4.TabIndex = 8;
            label4.Text = "私钥:";
            // 
            // textRSAPrivateKey
            // 
            textRSAPrivateKey.Location = new Point(147, 223);
            textRSAPrivateKey.Margin = new Padding(4);
            textRSAPrivateKey.Multiline = true;
            textRSAPrivateKey.Name = "textRSAPrivateKey";
            textRSAPrivateKey.ScrollBars = ScrollBars.Both;
            textRSAPrivateKey.Size = new Size(1093, 70);
            textRSAPrivateKey.TabIndex = 7;
            // 
            // label3
            // 
            label3.AutoSize = true;
            label3.Location = new Point(19, 125);
            label3.Margin = new Padding(4, 0, 4, 0);
            label3.Name = "label3";
            label3.Size = new Size(43, 20);
            label3.TabIndex = 6;
            label3.Text = "公钥:";
            // 
            // textRSAPublicKey
            // 
            textRSAPublicKey.Location = new Point(147, 125);
            textRSAPublicKey.Margin = new Padding(4);
            textRSAPublicKey.Multiline = true;
            textRSAPublicKey.Name = "textRSAPublicKey";
            textRSAPublicKey.ScrollBars = ScrollBars.Both;
            textRSAPublicKey.Size = new Size(1093, 70);
            textRSAPublicKey.TabIndex = 5;
            // 
            // label2
            // 
            label2.AutoSize = true;
            label2.Location = new Point(379, 33);
            label2.Margin = new Padding(4, 0, 4, 0);
            label2.Name = "label2";
            label2.Size = new Size(73, 20);
            label2.TabIndex = 4;
            label2.Text = "密钥格式:";
            // 
            // comboRSAKeyFormat
            // 
            comboRSAKeyFormat.DropDownStyle = ComboBoxStyle.DropDownList;
            comboRSAKeyFormat.FormattingEnabled = true;
            comboRSAKeyFormat.Items.AddRange(new object[] { "PKCS1(非JAVA适用)", "PKCS8(JAVA适用)" });
            comboRSAKeyFormat.Location = new Point(462, 29);
            comboRSAKeyFormat.Margin = new Padding(4);
            comboRSAKeyFormat.Name = "comboRSAKeyFormat";
            comboRSAKeyFormat.Size = new Size(173, 28);
            comboRSAKeyFormat.TabIndex = 3;
            // 
            // label1
            // 
            label1.AutoSize = true;
            label1.Location = new Point(147, 33);
            label1.Margin = new Padding(4, 0, 4, 0);
            label1.Name = "label1";
            label1.Size = new Size(73, 20);
            label1.TabIndex = 2;
            label1.Text = "密钥长度:";
            // 
            // comboRSAKeySize
            // 
            comboRSAKeySize.DisplayMember = "Text";
            comboRSAKeySize.DropDownStyle = ComboBoxStyle.DropDownList;
            comboRSAKeySize.FormattingEnabled = true;
            comboRSAKeySize.Items.AddRange(new object[] { "1024", "2048", "4096" });
            comboRSAKeySize.Location = new Point(231, 29);
            comboRSAKeySize.Margin = new Padding(4);
            comboRSAKeySize.Name = "comboRSAKeySize";
            comboRSAKeySize.Size = new Size(127, 28);
            comboRSAKeySize.TabIndex = 1;
            comboRSAKeySize.ValueMember = "Value";
            // 
            // btnGenerateRSAKey
            // 
            btnGenerateRSAKey.Location = new Point(147, 80);
            btnGenerateRSAKey.Margin = new Padding(4);
            btnGenerateRSAKey.Name = "btnGenerateRSAKey";
            btnGenerateRSAKey.Size = new Size(129, 28);
            btnGenerateRSAKey.TabIndex = 0;
            btnGenerateRSAKey.Text = "生成密钥对";
            btnGenerateRSAKey.UseVisualStyleBackColor = true;
            btnGenerateRSAKey.Click += btnGenerateRSAKey_Click;
            // 
            // tabSM4
            // 
            tabSM4.Controls.Add(groupBoxSM4Encrypt);
            tabSM4.Controls.Add(groupBoxSM4Keys);
            tabSM4.Location = new Point(4, 29);
            tabSM4.Margin = new Padding(4);
            tabSM4.Name = "tabSM4";
            tabSM4.Padding = new Padding(4);
            tabSM4.Size = new Size(1278, 1022);
            tabSM4.TabIndex = 1;
            tabSM4.Text = "SM4算法";
            tabSM4.UseVisualStyleBackColor = true;
            // 
            // groupBoxSM4Encrypt
            // 
            groupBoxSM4Encrypt.Controls.Add(labelSM4CiphertextFormat);
            groupBoxSM4Encrypt.Controls.Add(comboSM4CiphertextFormat);
            groupBoxSM4Encrypt.Controls.Add(labelSM4PlaintextFormat);
            groupBoxSM4Encrypt.Controls.Add(comboSM4PlaintextFormat);
            groupBoxSM4Encrypt.Controls.Add(label15);
            groupBoxSM4Encrypt.Controls.Add(comboSM4Padding);
            groupBoxSM4Encrypt.Controls.Add(label14);
            groupBoxSM4Encrypt.Controls.Add(comboSM4Mode);
            groupBoxSM4Encrypt.Controls.Add(label13);
            groupBoxSM4Encrypt.Controls.Add(textSM4CipherText);
            groupBoxSM4Encrypt.Controls.Add(label12);
            groupBoxSM4Encrypt.Controls.Add(textSM4PlainText);
            groupBoxSM4Encrypt.Controls.Add(btnSM4Decrypt);
            groupBoxSM4Encrypt.Controls.Add(btnSM4Encrypt);
            groupBoxSM4Encrypt.Location = new Point(8, 188);
            groupBoxSM4Encrypt.Margin = new Padding(4);
            groupBoxSM4Encrypt.Name = "groupBoxSM4Encrypt";
            groupBoxSM4Encrypt.Padding = new Padding(4);
            groupBoxSM4Encrypt.Size = new Size(1260, 294);
            groupBoxSM4Encrypt.TabIndex = 1;
            groupBoxSM4Encrypt.TabStop = false;
            groupBoxSM4Encrypt.Text = "SM4加密解密";
            // 
            // labelSM4CiphertextFormat
            // 
            labelSM4CiphertextFormat.AutoSize = true;
            labelSM4CiphertextFormat.Location = new Point(534, 71);
            labelSM4CiphertextFormat.Margin = new Padding(4, 0, 4, 0);
            labelSM4CiphertextFormat.Name = "labelSM4CiphertextFormat";
            labelSM4CiphertextFormat.Size = new Size(73, 20);
            labelSM4CiphertextFormat.TabIndex = 9;
            labelSM4CiphertextFormat.Text = "密文格式:";
            // 
            // comboSM4CiphertextFormat
            // 
            comboSM4CiphertextFormat.DropDownStyle = ComboBoxStyle.DropDownList;
            comboSM4CiphertextFormat.FormattingEnabled = true;
            comboSM4CiphertextFormat.Items.AddRange(new object[] { "Base64", "Hex" });
            comboSM4CiphertextFormat.Location = new Point(617, 67);
            comboSM4CiphertextFormat.Margin = new Padding(4);
            comboSM4CiphertextFormat.Name = "comboSM4CiphertextFormat";
            comboSM4CiphertextFormat.Size = new Size(127, 28);
            comboSM4CiphertextFormat.TabIndex = 8;
            // 
            // labelSM4PlaintextFormat
            // 
            labelSM4PlaintextFormat.AutoSize = true;
            labelSM4PlaintextFormat.Location = new Point(534, 33);
            labelSM4PlaintextFormat.Margin = new Padding(4, 0, 4, 0);
            labelSM4PlaintextFormat.Name = "labelSM4PlaintextFormat";
            labelSM4PlaintextFormat.Size = new Size(73, 20);
            labelSM4PlaintextFormat.TabIndex = 11;
            labelSM4PlaintextFormat.Text = "明文格式:";
            // 
            // comboSM4PlaintextFormat
            // 
            comboSM4PlaintextFormat.DropDownStyle = ComboBoxStyle.DropDownList;
            comboSM4PlaintextFormat.FormattingEnabled = true;
            comboSM4PlaintextFormat.Items.AddRange(new object[] { "Text", "Base64", "Hex" });
            comboSM4PlaintextFormat.Location = new Point(617, 29);
            comboSM4PlaintextFormat.Margin = new Padding(4);
            comboSM4PlaintextFormat.Name = "comboSM4PlaintextFormat";
            comboSM4PlaintextFormat.Size = new Size(127, 28);
            comboSM4PlaintextFormat.TabIndex = 10;
            // 
            // label15
            // 
            label15.AutoSize = true;
            label15.Location = new Point(276, 33);
            label15.Margin = new Padding(4, 0, 4, 0);
            label15.Name = "label15";
            label15.Size = new Size(73, 20);
            label15.TabIndex = 7;
            label15.Text = "填充模式:";
            // 
            // comboSM4Padding
            // 
            comboSM4Padding.DropDownStyle = ComboBoxStyle.DropDownList;
            comboSM4Padding.FormattingEnabled = true;
            comboSM4Padding.Items.AddRange(new object[] { "PKCS7", "PKCS5", "NoPadding" });
            comboSM4Padding.Location = new Point(360, 29);
            comboSM4Padding.Margin = new Padding(4);
            comboSM4Padding.Name = "comboSM4Padding";
            comboSM4Padding.Size = new Size(127, 28);
            comboSM4Padding.TabIndex = 6;
            // 
            // label14
            // 
            label14.AutoSize = true;
            label14.Location = new Point(19, 33);
            label14.Margin = new Padding(4, 0, 4, 0);
            label14.Name = "label14";
            label14.Size = new Size(73, 20);
            label14.TabIndex = 5;
            label14.Text = "加密模式:";
            // 
            // comboSM4Mode
            // 
            comboSM4Mode.DropDownStyle = ComboBoxStyle.DropDownList;
            comboSM4Mode.FormattingEnabled = true;
            comboSM4Mode.Items.AddRange(new object[] { "ECB", "CBC" });
            comboSM4Mode.Location = new Point(103, 29);
            comboSM4Mode.Margin = new Padding(4);
            comboSM4Mode.Name = "comboSM4Mode";
            comboSM4Mode.Size = new Size(127, 28);
            comboSM4Mode.TabIndex = 4;
            comboSM4Mode.SelectedIndexChanged += comboSM4Mode_SelectedIndexChanged;
            // 
            // label13
            // 
            label13.AutoSize = true;
            label13.Location = new Point(19, 186);
            label13.Margin = new Padding(4, 0, 4, 0);
            label13.Name = "label13";
            label13.Size = new Size(43, 20);
            label13.TabIndex = 5;
            label13.Text = "密文:";
            // 
            // textSM4CipherText
            // 
            textSM4CipherText.Location = new Point(103, 182);
            textSM4CipherText.Margin = new Padding(4);
            textSM4CipherText.Multiline = true;
            textSM4CipherText.Name = "textSM4CipherText";
            textSM4CipherText.ScrollBars = ScrollBars.Both;
            textSM4CipherText.Size = new Size(1137, 58);
            textSM4CipherText.TabIndex = 3;
            // 
            // label12
            // 
            label12.AutoSize = true;
            label12.Location = new Point(19, 115);
            label12.Margin = new Padding(4, 0, 4, 0);
            label12.Name = "label12";
            label12.Size = new Size(43, 20);
            label12.TabIndex = 3;
            label12.Text = "明文:";
            // 
            // textSM4PlainText
            // 
            textSM4PlainText.Location = new Point(103, 112);
            textSM4PlainText.Margin = new Padding(4);
            textSM4PlainText.Multiline = true;
            textSM4PlainText.Name = "textSM4PlainText";
            textSM4PlainText.ScrollBars = ScrollBars.Both;
            textSM4PlainText.Size = new Size(1137, 58);
            textSM4PlainText.TabIndex = 2;
            // 
            // btnSM4Decrypt
            // 
            btnSM4Decrypt.Location = new Point(885, 29);
            btnSM4Decrypt.Margin = new Padding(4);
            btnSM4Decrypt.Name = "btnSM4Decrypt";
            btnSM4Decrypt.Size = new Size(103, 28);
            btnSM4Decrypt.TabIndex = 1;
            btnSM4Decrypt.Text = "解密";
            btnSM4Decrypt.UseVisualStyleBackColor = true;
            btnSM4Decrypt.Click += btnSM4Decrypt_Click;
            // 
            // btnSM4Encrypt
            // 
            btnSM4Encrypt.Location = new Point(757, 29);
            btnSM4Encrypt.Margin = new Padding(4);
            btnSM4Encrypt.Name = "btnSM4Encrypt";
            btnSM4Encrypt.Size = new Size(103, 28);
            btnSM4Encrypt.TabIndex = 0;
            btnSM4Encrypt.Text = "加密";
            btnSM4Encrypt.UseVisualStyleBackColor = true;
            btnSM4Encrypt.Click += btnSM4Encrypt_Click;
            // 
            // groupBoxSM4Keys
            // 
            groupBoxSM4Keys.Controls.Add(labelSM4IVFormat);
            groupBoxSM4Keys.Controls.Add(comboSM4IVFormat);
            groupBoxSM4Keys.Controls.Add(labelSM4KeyFormat);
            groupBoxSM4Keys.Controls.Add(comboSM4KeyFormat);
            groupBoxSM4Keys.Controls.Add(label11);
            groupBoxSM4Keys.Controls.Add(textSM4IV);
            groupBoxSM4Keys.Controls.Add(label10);
            groupBoxSM4Keys.Controls.Add(textSM4Key);
            groupBoxSM4Keys.Controls.Add(btnGenerateSM4IV);
            groupBoxSM4Keys.Controls.Add(btnGenerateSM4Key);
            groupBoxSM4Keys.Location = new Point(8, 7);
            groupBoxSM4Keys.Margin = new Padding(4);
            groupBoxSM4Keys.Name = "groupBoxSM4Keys";
            groupBoxSM4Keys.Padding = new Padding(4);
            groupBoxSM4Keys.Size = new Size(1260, 159);
            groupBoxSM4Keys.TabIndex = 0;
            groupBoxSM4Keys.TabStop = false;
            groupBoxSM4Keys.Text = "SM4密钥生成";
            // 
            // labelSM4IVFormat
            // 
            labelSM4IVFormat.AutoSize = true;
            labelSM4IVFormat.Location = new Point(752, 104);
            labelSM4IVFormat.Margin = new Padding(4, 0, 4, 0);
            labelSM4IVFormat.Name = "labelSM4IVFormat";
            labelSM4IVFormat.Size = new Size(73, 20);
            labelSM4IVFormat.TabIndex = 11;
            labelSM4IVFormat.Text = "向量格式:";
            // 
            // comboSM4IVFormat
            // 
            comboSM4IVFormat.DropDownStyle = ComboBoxStyle.DropDownList;
            comboSM4IVFormat.FormattingEnabled = true;
            comboSM4IVFormat.Items.AddRange(new object[] { "Base64", "Hex", "Text" });
            comboSM4IVFormat.Location = new Point(836, 100);
            comboSM4IVFormat.Margin = new Padding(4);
            comboSM4IVFormat.Name = "comboSM4IVFormat";
            comboSM4IVFormat.Size = new Size(102, 28);
            comboSM4IVFormat.TabIndex = 10;
            comboSM4IVFormat.SelectedIndexChanged += comboSM4IVFormat_SelectedIndexChanged;
            // 
            // labelSM4KeyFormat
            // 
            labelSM4KeyFormat.AutoSize = true;
            labelSM4KeyFormat.Location = new Point(752, 45);
            labelSM4KeyFormat.Margin = new Padding(4, 0, 4, 0);
            labelSM4KeyFormat.Name = "labelSM4KeyFormat";
            labelSM4KeyFormat.Size = new Size(73, 20);
            labelSM4KeyFormat.TabIndex = 9;
            labelSM4KeyFormat.Text = "密钥格式:";
            // 
            // comboSM4KeyFormat
            // 
            comboSM4KeyFormat.DropDownStyle = ComboBoxStyle.DropDownList;
            comboSM4KeyFormat.FormattingEnabled = true;
            comboSM4KeyFormat.Items.AddRange(new object[] { "Base64", "Hex", "Text" });
            comboSM4KeyFormat.Location = new Point(836, 41);
            comboSM4KeyFormat.Margin = new Padding(4);
            comboSM4KeyFormat.Name = "comboSM4KeyFormat";
            comboSM4KeyFormat.Size = new Size(102, 28);
            comboSM4KeyFormat.TabIndex = 8;
            // 
            // label11
            // 
            label11.AutoSize = true;
            label11.Location = new Point(19, 104);
            label11.Margin = new Padding(4, 0, 4, 0);
            label11.Name = "label11";
            label11.Size = new Size(73, 20);
            label11.TabIndex = 5;
            label11.Text = "初始向量:";
            // 
            // textSM4IV
            // 
            textSM4IV.Location = new Point(103, 100);
            textSM4IV.Margin = new Padding(4);
            textSM4IV.Name = "textSM4IV";
            textSM4IV.Size = new Size(642, 27);
            textSM4IV.TabIndex = 4;
            // 
            // label10
            // 
            label10.AutoSize = true;
            label10.Location = new Point(19, 45);
            label10.Margin = new Padding(4, 0, 4, 0);
            label10.Name = "label10";
            label10.Size = new Size(76, 20);
            label10.TabIndex = 3;
            label10.Text = "SM4密钥:";
            // 
            // textSM4Key
            // 
            textSM4Key.Location = new Point(103, 41);
            textSM4Key.Margin = new Padding(4);
            textSM4Key.Name = "textSM4Key";
            textSM4Key.Size = new Size(642, 27);
            textSM4Key.TabIndex = 2;
            textSM4Key.TextChanged += textSM4Key_TextChanged;
            // 
            // btnGenerateSM4IV
            // 
            btnGenerateSM4IV.Location = new Point(967, 100);
            btnGenerateSM4IV.Margin = new Padding(4);
            btnGenerateSM4IV.Name = "btnGenerateSM4IV";
            btnGenerateSM4IV.Size = new Size(103, 28);
            btnGenerateSM4IV.TabIndex = 1;
            btnGenerateSM4IV.Text = "生成向量";
            btnGenerateSM4IV.UseVisualStyleBackColor = true;
            btnGenerateSM4IV.Click += btnGenerateSM4IV_Click;
            // 
            // btnGenerateSM4Key
            // 
            btnGenerateSM4Key.Location = new Point(967, 41);
            btnGenerateSM4Key.Margin = new Padding(4);
            btnGenerateSM4Key.Name = "btnGenerateSM4Key";
            btnGenerateSM4Key.Size = new Size(103, 28);
            btnGenerateSM4Key.TabIndex = 0;
            btnGenerateSM4Key.Text = "生成密钥";
            btnGenerateSM4Key.UseVisualStyleBackColor = true;
            btnGenerateSM4Key.Click += btnGenerateSM4Key_Click;
            // 
            // tabSM2
            // 
            tabSM2.Controls.Add(groupBoxSM2Sign);
            tabSM2.Controls.Add(groupBoxSM2Encrypt);
            tabSM2.Controls.Add(groupBoxSM2Keys);
            tabSM2.Location = new Point(4, 29);
            tabSM2.Margin = new Padding(4);
            tabSM2.Name = "tabSM2";
            tabSM2.Padding = new Padding(4);
            tabSM2.Size = new Size(1278, 1022);
            tabSM2.TabIndex = 2;
            tabSM2.Text = "SM2算法";
            tabSM2.UseVisualStyleBackColor = true;
            // 
            // groupBoxSM2Sign
            // 
            groupBoxSM2Sign.Controls.Add(labelSM2VerifyResult);
            groupBoxSM2Sign.Controls.Add(label24);
            groupBoxSM2Sign.Controls.Add(textSM2Signature);
            groupBoxSM2Sign.Controls.Add(label23);
            groupBoxSM2Sign.Controls.Add(textSM2SignData);
            groupBoxSM2Sign.Controls.Add(btnSM2Verify);
            groupBoxSM2Sign.Controls.Add(btnSM2Sign);
            groupBoxSM2Sign.Controls.Add(label22);
            groupBoxSM2Sign.Controls.Add(comboSM2SignFormat);
            groupBoxSM2Sign.Location = new Point(8, 468);
            groupBoxSM2Sign.Margin = new Padding(4);
            groupBoxSM2Sign.Name = "groupBoxSM2Sign";
            groupBoxSM2Sign.Padding = new Padding(4);
            groupBoxSM2Sign.Size = new Size(1260, 375);
            groupBoxSM2Sign.TabIndex = 2;
            groupBoxSM2Sign.TabStop = false;
            groupBoxSM2Sign.Text = "SM2数字签名";
            // 
            // labelSM2VerifyResult
            // 
            labelSM2VerifyResult.AutoSize = true;
            labelSM2VerifyResult.Location = new Point(514, 302);
            labelSM2VerifyResult.Margin = new Padding(4, 0, 4, 0);
            labelSM2VerifyResult.Name = "labelSM2VerifyResult";
            labelSM2VerifyResult.Size = new Size(73, 20);
            labelSM2VerifyResult.TabIndex = 8;
            labelSM2VerifyResult.Text = "验签结果:";
            // 
            // label24
            // 
            label24.AutoSize = true;
            label24.Location = new Point(19, 224);
            label24.Margin = new Padding(4, 0, 4, 0);
            label24.Name = "label24";
            label24.Size = new Size(43, 20);
            label24.TabIndex = 7;
            label24.Text = "签名:";
            // 
            // textSM2Signature
            // 
            textSM2Signature.Location = new Point(103, 220);
            textSM2Signature.Margin = new Padding(4);
            textSM2Signature.Multiline = true;
            textSM2Signature.Name = "textSM2Signature";
            textSM2Signature.ScrollBars = ScrollBars.Both;
            textSM2Signature.Size = new Size(1137, 58);
            textSM2Signature.TabIndex = 6;
            // 
            // label23
            // 
            label23.AutoSize = true;
            label23.Location = new Point(19, 74);
            label23.Margin = new Padding(4, 0, 4, 0);
            label23.Name = "label23";
            label23.Size = new Size(73, 20);
            label23.TabIndex = 5;
            label23.Text = "原文数据:";
            // 
            // textSM2SignData
            // 
            textSM2SignData.Location = new Point(103, 71);
            textSM2SignData.Margin = new Padding(4);
            textSM2SignData.Multiline = true;
            textSM2SignData.Name = "textSM2SignData";
            textSM2SignData.ScrollBars = ScrollBars.Both;
            textSM2SignData.Size = new Size(1137, 130);
            textSM2SignData.TabIndex = 4;
            // 
            // btnSM2Verify
            // 
            btnSM2Verify.Location = new Point(514, 29);
            btnSM2Verify.Margin = new Padding(4);
            btnSM2Verify.Name = "btnSM2Verify";
            btnSM2Verify.Size = new Size(103, 28);
            btnSM2Verify.TabIndex = 3;
            btnSM2Verify.Text = "验签";
            btnSM2Verify.UseVisualStyleBackColor = true;
            btnSM2Verify.Click += btnSM2Verify_Click;
            // 
            // btnSM2Sign
            // 
            btnSM2Sign.Location = new Point(360, 29);
            btnSM2Sign.Margin = new Padding(4);
            btnSM2Sign.Name = "btnSM2Sign";
            btnSM2Sign.Size = new Size(103, 28);
            btnSM2Sign.TabIndex = 2;
            btnSM2Sign.Text = "签名";
            btnSM2Sign.UseVisualStyleBackColor = true;
            btnSM2Sign.Click += btnSM2Sign_Click;
            // 
            // label22
            // 
            label22.AutoSize = true;
            label22.Location = new Point(19, 33);
            label22.Margin = new Padding(4, 0, 4, 0);
            label22.Name = "label22";
            label22.Size = new Size(73, 20);
            label22.TabIndex = 1;
            label22.Text = "签名格式:";
            // 
            // comboSM2SignFormat
            // 
            comboSM2SignFormat.DropDownStyle = ComboBoxStyle.DropDownList;
            comboSM2SignFormat.FormattingEnabled = true;
            comboSM2SignFormat.Items.AddRange(new object[] { "ASN1", "RS" });
            comboSM2SignFormat.Location = new Point(103, 29);
            comboSM2SignFormat.Margin = new Padding(4);
            comboSM2SignFormat.Name = "comboSM2SignFormat";
            comboSM2SignFormat.Size = new Size(127, 28);
            comboSM2SignFormat.TabIndex = 0;
            // 
            // groupBoxSM2Encrypt
            // 
            groupBoxSM2Encrypt.Controls.Add(label21);
            groupBoxSM2Encrypt.Controls.Add(textSM2CipherText);
            groupBoxSM2Encrypt.Controls.Add(label20);
            groupBoxSM2Encrypt.Controls.Add(textSM2PlainText);
            groupBoxSM2Encrypt.Controls.Add(btnSM2Decrypt);
            groupBoxSM2Encrypt.Controls.Add(btnSM2Encrypt);
            groupBoxSM2Encrypt.Controls.Add(label19);
            groupBoxSM2Encrypt.Controls.Add(comboSM2CipherFormat);
            groupBoxSM2Encrypt.Location = new Point(8, 249);
            groupBoxSM2Encrypt.Margin = new Padding(4);
            groupBoxSM2Encrypt.Name = "groupBoxSM2Encrypt";
            groupBoxSM2Encrypt.Padding = new Padding(4);
            groupBoxSM2Encrypt.Size = new Size(1260, 212);
            groupBoxSM2Encrypt.TabIndex = 1;
            groupBoxSM2Encrypt.TabStop = false;
            groupBoxSM2Encrypt.Text = "SM2加密解密";
            // 
            // label21
            // 
            label21.AutoSize = true;
            label21.Location = new Point(19, 127);
            label21.Margin = new Padding(4, 0, 4, 0);
            label21.Name = "label21";
            label21.Size = new Size(43, 20);
            label21.TabIndex = 7;
            label21.Text = "密文:";
            // 
            // textSM2CipherText
            // 
            textSM2CipherText.Location = new Point(103, 124);
            textSM2CipherText.Margin = new Padding(4);
            textSM2CipherText.Multiline = true;
            textSM2CipherText.Name = "textSM2CipherText";
            textSM2CipherText.ScrollBars = ScrollBars.Both;
            textSM2CipherText.Size = new Size(1137, 80);
            textSM2CipherText.TabIndex = 6;
            // 
            // label20
            // 
            label20.AutoSize = true;
            label20.Location = new Point(19, 74);
            label20.Margin = new Padding(4, 0, 4, 0);
            label20.Name = "label20";
            label20.Size = new Size(43, 20);
            label20.TabIndex = 5;
            label20.Text = "明文:";
            // 
            // textSM2PlainText
            // 
            textSM2PlainText.Location = new Point(103, 71);
            textSM2PlainText.Margin = new Padding(4);
            textSM2PlainText.Multiline = true;
            textSM2PlainText.Name = "textSM2PlainText";
            textSM2PlainText.ScrollBars = ScrollBars.Both;
            textSM2PlainText.Size = new Size(1137, 40);
            textSM2PlainText.TabIndex = 4;
            // 
            // btnSM2Decrypt
            // 
            btnSM2Decrypt.Location = new Point(514, 29);
            btnSM2Decrypt.Margin = new Padding(4);
            btnSM2Decrypt.Name = "btnSM2Decrypt";
            btnSM2Decrypt.Size = new Size(103, 28);
            btnSM2Decrypt.TabIndex = 3;
            btnSM2Decrypt.Text = "解密";
            btnSM2Decrypt.UseVisualStyleBackColor = true;
            btnSM2Decrypt.Click += btnSM2Decrypt_Click;
            // 
            // btnSM2Encrypt
            // 
            btnSM2Encrypt.Location = new Point(360, 29);
            btnSM2Encrypt.Margin = new Padding(4);
            btnSM2Encrypt.Name = "btnSM2Encrypt";
            btnSM2Encrypt.Size = new Size(103, 28);
            btnSM2Encrypt.TabIndex = 2;
            btnSM2Encrypt.Text = "加密";
            btnSM2Encrypt.UseVisualStyleBackColor = true;
            btnSM2Encrypt.Click += btnSM2Encrypt_Click;
            // 
            // label19
            // 
            label19.AutoSize = true;
            label19.Location = new Point(19, 33);
            label19.Margin = new Padding(4, 0, 4, 0);
            label19.Name = "label19";
            label19.Size = new Size(73, 20);
            label19.TabIndex = 1;
            label19.Text = "密文格式:";
            // 
            // comboSM2CipherFormat
            // 
            comboSM2CipherFormat.DropDownStyle = ComboBoxStyle.DropDownList;
            comboSM2CipherFormat.FormattingEnabled = true;
            comboSM2CipherFormat.Items.AddRange(new object[] { "C1C3C2", "C1C2C3", "ASN1" });
            comboSM2CipherFormat.Location = new Point(103, 29);
            comboSM2CipherFormat.Margin = new Padding(4);
            comboSM2CipherFormat.Name = "comboSM2CipherFormat";
            comboSM2CipherFormat.Size = new Size(127, 28);
            comboSM2CipherFormat.TabIndex = 0;
            // 
            // groupBoxSM2Keys
            // 
            groupBoxSM2Keys.Controls.Add(btnExportSM2Key);
            groupBoxSM2Keys.Controls.Add(btnImportSM2Key);
            groupBoxSM2Keys.Controls.Add(label18);
            groupBoxSM2Keys.Controls.Add(textSM2PrivateKey);
            groupBoxSM2Keys.Controls.Add(label17);
            groupBoxSM2Keys.Controls.Add(textSM2PublicKey);
            groupBoxSM2Keys.Controls.Add(label16);
            groupBoxSM2Keys.Controls.Add(comboSM2KeyFormat);
            groupBoxSM2Keys.Controls.Add(btnGenerateSM2Key);
            groupBoxSM2Keys.Location = new Point(8, 7);
            groupBoxSM2Keys.Margin = new Padding(4);
            groupBoxSM2Keys.Name = "groupBoxSM2Keys";
            groupBoxSM2Keys.Padding = new Padding(4);
            groupBoxSM2Keys.Size = new Size(1260, 235);
            groupBoxSM2Keys.TabIndex = 0;
            groupBoxSM2Keys.TabStop = false;
            groupBoxSM2Keys.Text = "SM2密钥生成";
            // 
            // btnExportSM2Key
            // 
            btnExportSM2Key.Location = new Point(643, 29);
            btnExportSM2Key.Margin = new Padding(4);
            btnExportSM2Key.Name = "btnExportSM2Key";
            btnExportSM2Key.Size = new Size(103, 28);
            btnExportSM2Key.TabIndex = 8;
            btnExportSM2Key.Text = "导出密钥";
            btnExportSM2Key.UseVisualStyleBackColor = true;
            btnExportSM2Key.Click += btnExportSM2Key_Click;
            // 
            // btnImportSM2Key
            // 
            btnImportSM2Key.Location = new Point(514, 29);
            btnImportSM2Key.Margin = new Padding(4);
            btnImportSM2Key.Name = "btnImportSM2Key";
            btnImportSM2Key.Size = new Size(103, 28);
            btnImportSM2Key.TabIndex = 7;
            btnImportSM2Key.Text = "导入密钥";
            btnImportSM2Key.UseVisualStyleBackColor = true;
            btnImportSM2Key.Click += btnImportSM2Key_Click;
            // 
            // label18
            // 
            label18.AutoSize = true;
            label18.Location = new Point(19, 162);
            label18.Margin = new Padding(4, 0, 4, 0);
            label18.Name = "label18";
            label18.Size = new Size(43, 20);
            label18.TabIndex = 6;
            label18.Text = "私钥:";
            // 
            // textSM2PrivateKey
            // 
            textSM2PrivateKey.Location = new Point(103, 159);
            textSM2PrivateKey.Margin = new Padding(4);
            textSM2PrivateKey.Multiline = true;
            textSM2PrivateKey.Name = "textSM2PrivateKey";
            textSM2PrivateKey.ScrollBars = ScrollBars.Both;
            textSM2PrivateKey.Size = new Size(1137, 70);
            textSM2PrivateKey.TabIndex = 5;
            // 
            // label17
            // 
            label17.AutoSize = true;
            label17.Location = new Point(19, 80);
            label17.Margin = new Padding(4, 0, 4, 0);
            label17.Name = "label17";
            label17.Size = new Size(43, 20);
            label17.TabIndex = 4;
            label17.Text = "公钥:";
            // 
            // textSM2PublicKey
            // 
            textSM2PublicKey.Location = new Point(103, 76);
            textSM2PublicKey.Margin = new Padding(4);
            textSM2PublicKey.Multiline = true;
            textSM2PublicKey.Name = "textSM2PublicKey";
            textSM2PublicKey.ScrollBars = ScrollBars.Both;
            textSM2PublicKey.Size = new Size(1137, 70);
            textSM2PublicKey.TabIndex = 3;
            // 
            // label16
            // 
            label16.AutoSize = true;
            label16.Location = new Point(19, 33);
            label16.Margin = new Padding(4, 0, 4, 0);
            label16.Name = "label16";
            label16.Size = new Size(73, 20);
            label16.TabIndex = 2;
            label16.Text = "密钥格式:";
            // 
            // comboSM2KeyFormat
            // 
            comboSM2KeyFormat.DropDownStyle = ComboBoxStyle.DropDownList;
            comboSM2KeyFormat.FormattingEnabled = true;
            comboSM2KeyFormat.Items.AddRange(new object[] { "Base64", "Hex" });
            comboSM2KeyFormat.Location = new Point(103, 29);
            comboSM2KeyFormat.Margin = new Padding(4);
            comboSM2KeyFormat.Name = "comboSM2KeyFormat";
            comboSM2KeyFormat.Size = new Size(127, 28);
            comboSM2KeyFormat.TabIndex = 1;
            // 
            // btnGenerateSM2Key
            // 
            btnGenerateSM2Key.Location = new Point(360, 29);
            btnGenerateSM2Key.Margin = new Padding(4);
            btnGenerateSM2Key.Name = "btnGenerateSM2Key";
            btnGenerateSM2Key.Size = new Size(129, 28);
            btnGenerateSM2Key.TabIndex = 0;
            btnGenerateSM2Key.Text = "生成密钥对";
            btnGenerateSM2Key.UseVisualStyleBackColor = true;
            btnGenerateSM2Key.Click += btnGenerateSM2Key_Click;
            // 
            // tabMedicare
            // 
            tabMedicare.Controls.Add(groupBoxMedicareParams);
            tabMedicare.Controls.Add(groupBoxMedicareKeys);
            tabMedicare.Controls.Add(groupBoxMedicareAction);
            tabMedicare.Location = new Point(4, 29);
            tabMedicare.Margin = new Padding(4);
            tabMedicare.Name = "tabMedicare";
            tabMedicare.Padding = new Padding(3, 4, 3, 4);
            tabMedicare.Size = new Size(1278, 1022);
            tabMedicare.TabIndex = 3;
            tabMedicare.Text = "医保接口";
            tabMedicare.UseVisualStyleBackColor = true;
            // 
            // groupBoxMedicareParams
            // 
            groupBoxMedicareParams.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            groupBoxMedicareParams.Controls.Add(labelMedicareAppId);
            groupBoxMedicareParams.Controls.Add(textMedicareAppId);
            groupBoxMedicareParams.Controls.Add(labelMedicareAppSecret);
            groupBoxMedicareParams.Controls.Add(textMedicareAppSecret);
            groupBoxMedicareParams.Controls.Add(labelMedicareVersion);
            groupBoxMedicareParams.Controls.Add(textMedicareVersion);
            groupBoxMedicareParams.Controls.Add(labelMedicareTimestamp);
            groupBoxMedicareParams.Controls.Add(textMedicareTimestamp);
            groupBoxMedicareParams.Controls.Add(labelMedicareSignType);
            groupBoxMedicareParams.Controls.Add(textMedicareSignType);
            groupBoxMedicareParams.Controls.Add(labelMedicareEncType);
            groupBoxMedicareParams.Controls.Add(textMedicareEncType);
            groupBoxMedicareParams.Controls.Add(labelMedicareData);
            groupBoxMedicareParams.Controls.Add(textMedicareData);
            groupBoxMedicareParams.Location = new Point(8, 6);
            groupBoxMedicareParams.Margin = new Padding(4);
            groupBoxMedicareParams.Name = "groupBoxMedicareParams";
            groupBoxMedicareParams.Padding = new Padding(4);
            groupBoxMedicareParams.Size = new Size(1264, 249);
            groupBoxMedicareParams.TabIndex = 0;
            groupBoxMedicareParams.TabStop = false;
            groupBoxMedicareParams.Text = "请求参数";
            // 
            // labelMedicareAppId
            // 
            labelMedicareAppId.AutoSize = true;
            labelMedicareAppId.Location = new Point(15, 31);
            labelMedicareAppId.Margin = new Padding(4, 0, 4, 0);
            labelMedicareAppId.Name = "labelMedicareAppId";
            labelMedicareAppId.Size = new Size(55, 20);
            labelMedicareAppId.TabIndex = 0;
            labelMedicareAppId.Text = "appId:";
            // 
            // textMedicareAppId
            // 
            textMedicareAppId.Location = new Point(100, 27);
            textMedicareAppId.Margin = new Padding(4);
            textMedicareAppId.Name = "textMedicareAppId";
            textMedicareAppId.Size = new Size(350, 27);
            textMedicareAppId.TabIndex = 1;
            // 
            // labelMedicareAppSecret
            // 
            labelMedicareAppSecret.AutoSize = true;
            labelMedicareAppSecret.Location = new Point(471, 31);
            labelMedicareAppSecret.Margin = new Padding(4, 0, 4, 0);
            labelMedicareAppSecret.Name = "labelMedicareAppSecret";
            labelMedicareAppSecret.Size = new Size(88, 20);
            labelMedicareAppSecret.TabIndex = 2;
            labelMedicareAppSecret.Text = "appSecret:";
            // 
            // textMedicareAppSecret
            // 
            textMedicareAppSecret.Location = new Point(561, 27);
            textMedicareAppSecret.Margin = new Padding(4);
            textMedicareAppSecret.Name = "textMedicareAppSecret";
            textMedicareAppSecret.Size = new Size(350, 27);
            textMedicareAppSecret.TabIndex = 3;
            // 
            // labelMedicareVersion
            // 
            labelMedicareVersion.AutoSize = true;
            labelMedicareVersion.Location = new Point(15, 65);
            labelMedicareVersion.Margin = new Padding(4, 0, 4, 0);
            labelMedicareVersion.Name = "labelMedicareVersion";
            labelMedicareVersion.Size = new Size(66, 20);
            labelMedicareVersion.TabIndex = 4;
            labelMedicareVersion.Text = "version:";
            // 
            // textMedicareVersion
            // 
            textMedicareVersion.Location = new Point(100, 62);
            textMedicareVersion.Margin = new Padding(4);
            textMedicareVersion.Name = "textMedicareVersion";
            textMedicareVersion.Size = new Size(120, 27);
            textMedicareVersion.TabIndex = 5;
            // 
            // labelMedicareTimestamp
            // 
            labelMedicareTimestamp.AutoSize = true;
            labelMedicareTimestamp.Location = new Point(240, 65);
            labelMedicareTimestamp.Margin = new Padding(4, 0, 4, 0);
            labelMedicareTimestamp.Name = "labelMedicareTimestamp";
            labelMedicareTimestamp.Size = new Size(91, 20);
            labelMedicareTimestamp.TabIndex = 6;
            labelMedicareTimestamp.Text = "timestamp:";
            // 
            // textMedicareTimestamp
            // 
            textMedicareTimestamp.Location = new Point(339, 62);
            textMedicareTimestamp.Margin = new Padding(4);
            textMedicareTimestamp.Name = "textMedicareTimestamp";
            textMedicareTimestamp.Size = new Size(190, 27);
            textMedicareTimestamp.TabIndex = 7;
            textMedicareTimestamp.Leave += TextMedicareTimestamp_Leave;
            // 
            // labelMedicareSignType
            // 
            labelMedicareSignType.AutoSize = true;
            labelMedicareSignType.Location = new Point(550, 65);
            labelMedicareSignType.Margin = new Padding(4, 0, 4, 0);
            labelMedicareSignType.Name = "labelMedicareSignType";
            labelMedicareSignType.Size = new Size(79, 20);
            labelMedicareSignType.TabIndex = 8;
            labelMedicareSignType.Text = "signType:";
            // 
            // textMedicareSignType
            // 
            textMedicareSignType.Location = new Point(639, 62);
            textMedicareSignType.Margin = new Padding(4);
            textMedicareSignType.Name = "textMedicareSignType";
            textMedicareSignType.Size = new Size(111, 27);
            textMedicareSignType.TabIndex = 9;
            // 
            // labelMedicareEncType
            // 
            labelMedicareEncType.AutoSize = true;
            labelMedicareEncType.Location = new Point(770, 65);
            labelMedicareEncType.Margin = new Padding(4, 0, 4, 0);
            labelMedicareEncType.Name = "labelMedicareEncType";
            labelMedicareEncType.Size = new Size(75, 20);
            labelMedicareEncType.TabIndex = 10;
            labelMedicareEncType.Text = "encType:";
            // 
            // textMedicareEncType
            // 
            textMedicareEncType.Location = new Point(850, 62);
            textMedicareEncType.Margin = new Padding(4);
            textMedicareEncType.Name = "textMedicareEncType";
            textMedicareEncType.Size = new Size(120, 27);
            textMedicareEncType.TabIndex = 11;
            // 
            // labelMedicareData
            // 
            labelMedicareData.AutoSize = true;
            labelMedicareData.Location = new Point(15, 100);
            labelMedicareData.Margin = new Padding(4, 0, 4, 0);
            labelMedicareData.Name = "labelMedicareData";
            labelMedicareData.Size = new Size(73, 20);
            labelMedicareData.TabIndex = 12;
            labelMedicareData.Text = "业务数据:";
            // 
            // textMedicareData
            // 
            textMedicareData.Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
            textMedicareData.Location = new Point(100, 96);
            textMedicareData.Margin = new Padding(4);
            textMedicareData.Multiline = true;
            textMedicareData.Name = "textMedicareData";
            textMedicareData.ScrollBars = ScrollBars.Both;
            textMedicareData.Size = new Size(1150, 140);
            textMedicareData.TabIndex = 13;
            // 
            // groupBoxMedicareKeys
            // 
            groupBoxMedicareKeys.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            groupBoxMedicareKeys.Controls.Add(btnGenerateMedicareSM4Key);
            groupBoxMedicareKeys.Controls.Add(labelMedicareSM4Key);
            groupBoxMedicareKeys.Controls.Add(textMedicareSM4Key);
            groupBoxMedicareKeys.Controls.Add(btnGenerateMedicareKey);
            groupBoxMedicareKeys.Controls.Add(btnImportMedicareKey);
            groupBoxMedicareKeys.Controls.Add(btnExportMedicareKey);
            groupBoxMedicareKeys.Controls.Add(labelMedicarePublicKey);
            groupBoxMedicareKeys.Controls.Add(textMedicarePublicKey);
            groupBoxMedicareKeys.Controls.Add(labelMedicarePrivateKey);
            groupBoxMedicareKeys.Controls.Add(textMedicarePrivateKey);
            groupBoxMedicareKeys.Location = new Point(8, 262);
            groupBoxMedicareKeys.Margin = new Padding(4);
            groupBoxMedicareKeys.Name = "groupBoxMedicareKeys";
            groupBoxMedicareKeys.Padding = new Padding(4);
            groupBoxMedicareKeys.Size = new Size(1264, 185);
            groupBoxMedicareKeys.TabIndex = 1;
            groupBoxMedicareKeys.TabStop = false;
            groupBoxMedicareKeys.Text = "医保SM2/SM4密钥";
            // 
            // btnGenerateMedicareSM4Key
            // 
            btnGenerateMedicareSM4Key.Location = new Point(429, 25);
            btnGenerateMedicareSM4Key.Margin = new Padding(3, 4, 3, 4);
            btnGenerateMedicareSM4Key.Name = "btnGenerateMedicareSM4Key";
            btnGenerateMedicareSM4Key.Size = new Size(150, 31);
            btnGenerateMedicareSM4Key.TabIndex = 0;
            btnGenerateMedicareSM4Key.Text = "生成医保SM4密钥";
            btnGenerateMedicareSM4Key.UseVisualStyleBackColor = true;
            btnGenerateMedicareSM4Key.Click += btnGenerateMedicareSM4Key_Click;
            // 
            // labelMedicareSM4Key
            // 
            labelMedicareSM4Key.AutoSize = true;
            labelMedicareSM4Key.Location = new Point(15, 145);
            labelMedicareSM4Key.Name = "labelMedicareSM4Key";
            labelMedicareSM4Key.Size = new Size(145, 20);
            labelMedicareSM4Key.TabIndex = 6;
            labelMedicareSM4Key.Text = "医保SM4密钥(Hex):";
            // 
            // textMedicareSM4Key
            // 
            textMedicareSM4Key.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            textMedicareSM4Key.Location = new Point(167, 142);
            textMedicareSM4Key.Margin = new Padding(4);
            textMedicareSM4Key.Name = "textMedicareSM4Key";
            textMedicareSM4Key.Size = new Size(1083, 27);
            textMedicareSM4Key.TabIndex = 7;
            // 
            // btnGenerateMedicareKey
            // 
            btnGenerateMedicareKey.Location = new Point(15, 25);
            btnGenerateMedicareKey.Margin = new Padding(3, 4, 3, 4);
            btnGenerateMedicareKey.Name = "btnGenerateMedicareKey";
            btnGenerateMedicareKey.Size = new Size(120, 31);
            btnGenerateMedicareKey.TabIndex = 8;
            btnGenerateMedicareKey.Text = "生成密钥对";
            btnGenerateMedicareKey.UseVisualStyleBackColor = true;
            btnGenerateMedicareKey.Click += btnGenerateMedicareKey_Click;
            // 
            // btnImportMedicareKey
            // 
            btnImportMedicareKey.Location = new Point(150, 25);
            btnImportMedicareKey.Margin = new Padding(3, 4, 3, 4);
            btnImportMedicareKey.Name = "btnImportMedicareKey";
            btnImportMedicareKey.Size = new Size(120, 31);
            btnImportMedicareKey.TabIndex = 9;
            btnImportMedicareKey.Text = "导入密钥";
            btnImportMedicareKey.UseVisualStyleBackColor = true;
            btnImportMedicareKey.Click += btnImportMedicareKey_Click;
            // 
            // btnExportMedicareKey
            // 
            btnExportMedicareKey.Location = new Point(285, 25);
            btnExportMedicareKey.Margin = new Padding(3, 4, 3, 4);
            btnExportMedicareKey.Name = "btnExportMedicareKey";
            btnExportMedicareKey.Size = new Size(120, 31);
            btnExportMedicareKey.TabIndex = 10;
            btnExportMedicareKey.Text = "导出密钥";
            btnExportMedicareKey.UseVisualStyleBackColor = true;
            btnExportMedicareKey.Click += btnExportMedicareKey_Click;
            // 
            // labelMedicarePublicKey
            // 
            labelMedicarePublicKey.AutoSize = true;
            labelMedicarePublicKey.Location = new Point(15, 65);
            labelMedicarePublicKey.Name = "labelMedicarePublicKey";
            labelMedicarePublicKey.Size = new Size(82, 20);
            labelMedicarePublicKey.TabIndex = 11;
            labelMedicarePublicKey.Text = "公钥(Hex):";
            // 
            // textMedicarePublicKey
            // 
            textMedicarePublicKey.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            textMedicarePublicKey.Location = new Point(100, 62);
            textMedicarePublicKey.Margin = new Padding(4);
            textMedicarePublicKey.Name = "textMedicarePublicKey";
            textMedicarePublicKey.Size = new Size(1150, 27);
            textMedicarePublicKey.TabIndex = 12;
            // 
            // labelMedicarePrivateKey
            // 
            labelMedicarePrivateKey.AutoSize = true;
            labelMedicarePrivateKey.Location = new Point(15, 105);
            labelMedicarePrivateKey.Name = "labelMedicarePrivateKey";
            labelMedicarePrivateKey.Size = new Size(82, 20);
            labelMedicarePrivateKey.TabIndex = 13;
            labelMedicarePrivateKey.Text = "私钥(Hex):";
            // 
            // textMedicarePrivateKey
            // 
            textMedicarePrivateKey.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            textMedicarePrivateKey.Location = new Point(100, 102);
            textMedicarePrivateKey.Margin = new Padding(4);
            textMedicarePrivateKey.Name = "textMedicarePrivateKey";
            textMedicarePrivateKey.Size = new Size(1150, 27);
            textMedicarePrivateKey.TabIndex = 14;
            // 
            // groupBoxMedicareAction
            // 
            groupBoxMedicareAction.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            groupBoxMedicareAction.Controls.Add(btnMedicareSign);
            groupBoxMedicareAction.Controls.Add(btnMedicareVerify);
            groupBoxMedicareAction.Controls.Add(btnMedicareEncrypt);
            groupBoxMedicareAction.Controls.Add(btnMedicareDecrypt);
            groupBoxMedicareAction.Controls.Add(labelMedicareSignatureString);
            groupBoxMedicareAction.Controls.Add(textMedicareSignatureString);
            groupBoxMedicareAction.Controls.Add(labelMedicareSignData);
            groupBoxMedicareAction.Controls.Add(textMedicareSignData);
            groupBoxMedicareAction.Controls.Add(labelMedicareEncData);
            groupBoxMedicareAction.Controls.Add(textMedicareEncData);
            groupBoxMedicareAction.Controls.Add(labelMedicareDecData);
            groupBoxMedicareAction.Controls.Add(textMedicareDecData);
            groupBoxMedicareAction.Location = new Point(8, 458);
            groupBoxMedicareAction.Margin = new Padding(4);
            groupBoxMedicareAction.Name = "groupBoxMedicareAction";
            groupBoxMedicareAction.Padding = new Padding(4);
            groupBoxMedicareAction.Size = new Size(1264, 613);
            groupBoxMedicareAction.TabIndex = 2;
            groupBoxMedicareAction.TabStop = false;
            groupBoxMedicareAction.Text = "操作和结果";
            // 
            // btnMedicareSign
            // 
            btnMedicareSign.Location = new Point(180, 25);
            btnMedicareSign.Margin = new Padding(3, 4, 3, 4);
            btnMedicareSign.Name = "btnMedicareSign";
            btnMedicareSign.Size = new Size(100, 31);
            btnMedicareSign.TabIndex = 1;
            btnMedicareSign.Text = "签名";
            btnMedicareSign.UseVisualStyleBackColor = true;
            btnMedicareSign.Click += btnMedicareSign_Click;
            // 
            // btnMedicareVerify
            // 
            btnMedicareVerify.Location = new Point(294, 25);
            btnMedicareVerify.Margin = new Padding(3, 4, 3, 4);
            btnMedicareVerify.Name = "btnMedicareVerify";
            btnMedicareVerify.Size = new Size(100, 31);
            btnMedicareVerify.TabIndex = 2;
            btnMedicareVerify.Text = "验签";
            btnMedicareVerify.UseVisualStyleBackColor = true;
            btnMedicareVerify.Click += btnMedicareVerify_Click;
            // 
            // btnMedicareEncrypt
            // 
            btnMedicareEncrypt.Location = new Point(410, 25);
            btnMedicareEncrypt.Margin = new Padding(3, 4, 3, 4);
            btnMedicareEncrypt.Name = "btnMedicareEncrypt";
            btnMedicareEncrypt.Size = new Size(100, 31);
            btnMedicareEncrypt.TabIndex = 3;
            btnMedicareEncrypt.Text = "加密";
            btnMedicareEncrypt.UseVisualStyleBackColor = true;
            btnMedicareEncrypt.Click += btnMedicareEncrypt_Click;
            // 
            // btnMedicareDecrypt
            // 
            btnMedicareDecrypt.Location = new Point(525, 25);
            btnMedicareDecrypt.Margin = new Padding(3, 4, 3, 4);
            btnMedicareDecrypt.Name = "btnMedicareDecrypt";
            btnMedicareDecrypt.Size = new Size(100, 31);
            btnMedicareDecrypt.TabIndex = 4;
            btnMedicareDecrypt.Text = "解密";
            btnMedicareDecrypt.UseVisualStyleBackColor = true;
            btnMedicareDecrypt.Click += btnMedicareDecrypt_Click;
            // 
            // labelMedicareSignatureString
            // 
            labelMedicareSignatureString.AutoSize = true;
            labelMedicareSignatureString.Location = new Point(15, 71);
            labelMedicareSignatureString.Name = "labelMedicareSignatureString";
            labelMedicareSignatureString.Size = new Size(88, 20);
            labelMedicareSignatureString.TabIndex = 5;
            labelMedicareSignatureString.Text = "待签字符串:";
            // 
            // textMedicareSignatureString
            // 
            textMedicareSignatureString.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            textMedicareSignatureString.Location = new Point(15, 95);
            textMedicareSignatureString.Margin = new Padding(3, 4, 3, 4);
            textMedicareSignatureString.Multiline = true;
            textMedicareSignatureString.Name = "textMedicareSignatureString";
            textMedicareSignatureString.ScrollBars = ScrollBars.Both;
            textMedicareSignatureString.Size = new Size(1234, 60);
            textMedicareSignatureString.TabIndex = 6;
            // 
            // labelMedicareSignData
            // 
            labelMedicareSignData.AutoSize = true;
            labelMedicareSignData.Location = new Point(15, 165);
            labelMedicareSignData.Name = "labelMedicareSignData";
            labelMedicareSignData.Size = new Size(146, 20);
            labelMedicareSignData.TabIndex = 7;
            labelMedicareSignData.Text = "签名结果(signData):";
            // 
            // textMedicareSignData
            // 
            textMedicareSignData.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            textMedicareSignData.Location = new Point(15, 191);
            textMedicareSignData.Margin = new Padding(3, 4, 3, 4);
            textMedicareSignData.Multiline = true;
            textMedicareSignData.Name = "textMedicareSignData";
            textMedicareSignData.ScrollBars = ScrollBars.Both;
            textMedicareSignData.Size = new Size(1234, 60);
            textMedicareSignData.TabIndex = 8;
            // 
            // labelMedicareEncData
            // 
            labelMedicareEncData.AutoSize = true;
            labelMedicareEncData.Location = new Point(15, 266);
            labelMedicareEncData.Name = "labelMedicareEncData";
            labelMedicareEncData.Size = new Size(112, 20);
            labelMedicareEncData.TabIndex = 11;
            labelMedicareEncData.Text = "加密结果(Hex):";
            // 
            // textMedicareEncData
            // 
            textMedicareEncData.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            textMedicareEncData.Location = new Point(15, 289);
            textMedicareEncData.Margin = new Padding(3, 4, 3, 4);
            textMedicareEncData.Multiline = true;
            textMedicareEncData.Name = "textMedicareEncData";
            textMedicareEncData.ScrollBars = ScrollBars.Both;
            textMedicareEncData.Size = new Size(1234, 60);
            textMedicareEncData.TabIndex = 12;
            // 
            // labelMedicareDecData
            // 
            labelMedicareDecData.Location = new Point(15, 354);
            labelMedicareDecData.Name = "labelMedicareDecData";
            labelMedicareDecData.Size = new Size(100, 24);
            labelMedicareDecData.TabIndex = 13;
            labelMedicareDecData.Text = "解密结果:";
            // 
            // textMedicareDecData
            // 
            textMedicareDecData.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            textMedicareDecData.Location = new Point(15, 381);
            textMedicareDecData.Margin = new Padding(3, 4, 3, 4);
            textMedicareDecData.Multiline = true;
            textMedicareDecData.Name = "textMedicareDecData";
            textMedicareDecData.ScrollBars = ScrollBars.Both;
            textMedicareDecData.Size = new Size(1234, 93);
            textMedicareDecData.TabIndex = 14;
            // 
            // statusStrip1
            // 
            statusStrip1.ImageScalingSize = new Size(20, 20);
            statusStrip1.Items.AddRange(new ToolStripItem[] { toolStripStatusLabel1 });
            statusStrip1.Location = new Point(0, 1029);
            statusStrip1.Name = "statusStrip1";
            statusStrip1.Padding = new Padding(1, 0, 18, 0);
            statusStrip1.Size = new Size(1286, 26);
            statusStrip1.TabIndex = 1;
            statusStrip1.Text = "statusStrip1";
            // 
            // toolStripStatusLabel1
            // 
            toolStripStatusLabel1.Name = "toolStripStatusLabel1";
            toolStripStatusLabel1.Size = new Size(39, 20);
            toolStripStatusLabel1.Text = "就绪";
            // 
            // Form1
            // 
            AutoScaleDimensions = new SizeF(9F, 20F);
            AutoScaleMode = AutoScaleMode.Font;
            ClientSize = new Size(1286, 1055);
            Controls.Add(statusStrip1);
            Controls.Add(tabControl1);
            Margin = new Padding(4);
            Name = "Form1";
            StartPosition = FormStartPosition.CenterScreen;
            Text = "加解密工具";
            Load += Form1_Load;
            tabControl1.ResumeLayout(false);
            tabRSA.ResumeLayout(false);
            groupBoxRSASign.ResumeLayout(false);
            groupBoxRSASign.PerformLayout();
            groupBoxRSAEncrypt.ResumeLayout(false);
            groupBoxRSAEncrypt.PerformLayout();
            groupBoxRSAKeys.ResumeLayout(false);
            groupBoxRSAKeys.PerformLayout();
            tabSM4.ResumeLayout(false);
            groupBoxSM4Encrypt.ResumeLayout(false);
            groupBoxSM4Encrypt.PerformLayout();
            groupBoxSM4Keys.ResumeLayout(false);
            groupBoxSM4Keys.PerformLayout();
            tabSM2.ResumeLayout(false);
            groupBoxSM2Sign.ResumeLayout(false);
            groupBoxSM2Sign.PerformLayout();
            groupBoxSM2Encrypt.ResumeLayout(false);
            groupBoxSM2Encrypt.PerformLayout();
            groupBoxSM2Keys.ResumeLayout(false);
            groupBoxSM2Keys.PerformLayout();
            tabMedicare.ResumeLayout(false);
            groupBoxMedicareParams.ResumeLayout(false);
            groupBoxMedicareParams.PerformLayout();
            groupBoxMedicareKeys.ResumeLayout(false);
            groupBoxMedicareKeys.PerformLayout();
            groupBoxMedicareAction.ResumeLayout(false);
            groupBoxMedicareAction.PerformLayout();
            statusStrip1.ResumeLayout(false);
            statusStrip1.PerformLayout();
            ResumeLayout(false);
            PerformLayout();
        }


        #endregion

        private System.Windows.Forms.TabControl tabControl1;
        private System.Windows.Forms.TabPage tabRSA;
        private System.Windows.Forms.GroupBox groupBoxRSAKeys;
        private System.Windows.Forms.Label label4;
        private System.Windows.Forms.TextBox textRSAPrivateKey;
        private System.Windows.Forms.Label label3;
        private System.Windows.Forms.TextBox textRSAPublicKey;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.ComboBox comboRSAKeyFormat;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.ComboBox comboRSAKeySize;
        private System.Windows.Forms.Button btnGenerateRSAKey;
        private System.Windows.Forms.Button btnImportRSAKey;
        private System.Windows.Forms.Button btnExportRSAKey;
        private System.Windows.Forms.GroupBox groupBoxRSASign;
        private System.Windows.Forms.Label labelRSAVerifyResult;
        private System.Windows.Forms.Label label8;
        private System.Windows.Forms.TextBox textRSASignature;
        private System.Windows.Forms.Label label7;
        private System.Windows.Forms.TextBox textRSASignData;
        private System.Windows.Forms.Button btnRSAVerify;
        private System.Windows.Forms.Button btnRSASign;
        private System.Windows.Forms.GroupBox groupBoxRSAEncrypt;
        private System.Windows.Forms.Label label6;
        private System.Windows.Forms.TextBox textRSACipherText;
        private System.Windows.Forms.Label label5;
        private System.Windows.Forms.TextBox textRSAPlainText;
        private System.Windows.Forms.Button btnRSADecrypt;
        private System.Windows.Forms.Button btnRSAEncrypt;
        private System.Windows.Forms.TabPage tabSM4;
        private System.Windows.Forms.GroupBox groupBoxSM4Encrypt;
        private System.Windows.Forms.Label labelSM4DataFormat;
        private System.Windows.Forms.ComboBox comboSM4DataFormat;
        private System.Windows.Forms.Label labelSM4PlaintextFormat;
        private System.Windows.Forms.ComboBox comboSM4PlaintextFormat;
        private System.Windows.Forms.Label labelSM4CiphertextFormat;
        private System.Windows.Forms.ComboBox comboSM4CiphertextFormat;
        private System.Windows.Forms.Label label15;
        private System.Windows.Forms.ComboBox comboSM4Padding;
        private System.Windows.Forms.Label label14;
        private System.Windows.Forms.ComboBox comboSM4Mode;
        private System.Windows.Forms.Label label13;
        private System.Windows.Forms.TextBox textSM4CipherText;
        private System.Windows.Forms.Label label12;
        private System.Windows.Forms.TextBox textSM4PlainText;
        private System.Windows.Forms.Button btnSM4Decrypt;
        private System.Windows.Forms.Button btnSM4Encrypt;
        private System.Windows.Forms.GroupBox groupBoxSM4Keys;
        private System.Windows.Forms.Label label11;
        private System.Windows.Forms.TextBox textSM4IV;
        private System.Windows.Forms.Label label10;
        private System.Windows.Forms.TextBox textSM4Key;
        private System.Windows.Forms.Button btnGenerateSM4IV;
        private System.Windows.Forms.Button btnGenerateSM4Key;
        private System.Windows.Forms.ComboBox comboSM4KeyFormat;
        private System.Windows.Forms.Label labelSM4KeyFormat;
        private System.Windows.Forms.ComboBox comboSM4IVFormat;
        private System.Windows.Forms.Label labelSM4IVFormat;
        private System.Windows.Forms.TabPage tabSM2;
        private System.Windows.Forms.GroupBox groupBoxSM2Keys;
        private System.Windows.Forms.Button btnExportSM2Key;
        private System.Windows.Forms.Button btnImportSM2Key;
        private System.Windows.Forms.Label label18;
        private System.Windows.Forms.TextBox textSM2PrivateKey;
        private System.Windows.Forms.Label label17;
        private System.Windows.Forms.TextBox textSM2PublicKey;
        private System.Windows.Forms.Label label16;
        private System.Windows.Forms.ComboBox comboSM2KeyFormat;
        private System.Windows.Forms.Button btnGenerateSM2Key;
        private System.Windows.Forms.GroupBox groupBoxSM2Encrypt;
        private System.Windows.Forms.Label label21;
        private System.Windows.Forms.TextBox textSM2CipherText;
        private System.Windows.Forms.Label label20;
        private System.Windows.Forms.TextBox textSM2PlainText;
        private System.Windows.Forms.Button btnSM2Decrypt;
        private System.Windows.Forms.Button btnSM2Encrypt;
        private System.Windows.Forms.Label label19;
        private System.Windows.Forms.ComboBox comboSM2CipherFormat;
        private System.Windows.Forms.GroupBox groupBoxSM2Sign;
        private System.Windows.Forms.Label labelSM2VerifyResult;
        private System.Windows.Forms.Label label24;
        private System.Windows.Forms.TextBox textSM2Signature;
        private System.Windows.Forms.Label label23;
        private System.Windows.Forms.TextBox textSM2SignData;
        private System.Windows.Forms.Button btnSM2Verify;
        private System.Windows.Forms.Button btnSM2Sign;
        private System.Windows.Forms.Label label22;
        private System.Windows.Forms.ComboBox comboSM2SignFormat;
        private System.Windows.Forms.StatusStrip statusStrip1;
        private System.Windows.Forms.ToolStripStatusLabel toolStripStatusLabel1;
        private TabPage tabMedicare;
        private GroupBox groupBoxMedicareParams;
        private Label labelMedicareAppId;
        private TextBox textMedicareAppId;
        private Label labelMedicareAppSecret;
        private TextBox textMedicareAppSecret;
        private Label labelMedicareVersion;
        private TextBox textMedicareVersion;
        private Label labelMedicareTimestamp;
        private TextBox textMedicareTimestamp;
        private Label labelMedicareSignType;
        private TextBox textMedicareSignType;
        private Label labelMedicareEncType;
        private TextBox textMedicareEncType;
        private Label labelMedicareData;
        private TextBox textMedicareData;
        private GroupBox groupBoxMedicareKeys;
        private Button btnGenerateMedicareKey;
        private Button btnImportMedicareKey;
        private Button btnExportMedicareKey;
        private Label labelMedicarePublicKey;
        private TextBox textMedicarePublicKey;
        private Label labelMedicarePrivateKey;
        private TextBox textMedicarePrivateKey;
        private Label labelMedicareSM4Key;
        private TextBox textMedicareSM4Key;
        private GroupBox groupBoxMedicareAction;
        private Button btnGenerateMedicareSM4Key;
        private Button btnMedicareSign;
        private Button btnMedicareVerify;
        private Button btnMedicareEncrypt;
        private Button btnMedicareDecrypt;
        private Label labelMedicareSignatureString;
        private TextBox textMedicareSignatureString;
        private Label labelMedicareSignData;
        private TextBox textMedicareSignData;
        private Label labelMedicareEncData;
        private TextBox textMedicareEncData;
        private Label labelMedicareDecData;
        private TextBox textMedicareDecData;
        private Label label25;
        private ComboBox comboRSAKeyPadding;
        private Label label26;
        private ComboBox comboRSAKeyOutputFormat;
        private ComboBox comboRSAEncryptOutputFormat;
        private Label label27;
        private Label label28;
        private ComboBox comboRSASignOutputFormat;
        private Label label29;
        private ComboBox comboRSASignAlgmFormat;
    }

    /// <summary>
    /// 定义一个表示下拉选项的类
    /// </summary>
    public class ComboBoxItem
    {
        public string Text { get; set; }  // 显示的文字
        public object Value { get; set; } // 关联的值，使用 object 类型更通用

        // 可选：重写 ToString 方法，通常绑定后不需要，但有时可备用
        public override string ToString()
        {
            return Text;
        }
    }
}
