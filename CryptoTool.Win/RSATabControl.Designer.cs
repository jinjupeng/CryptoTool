namespace CryptoTool.Win
{
    partial class RSATabControl : UserControl
    {
        /// <summary> 
        /// 必需的设计器变量。
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary> 
        /// 清理所有正在使用的资源。
        /// </summary>
        /// <param name="disposing">如果应释放托管资源，为 true；否则为 false。</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region 组件设计器生成的代码

        /// <summary> 
        /// 设计器支持所需的方法 - 不要修改
        /// 使用代码编辑器修改此方法的内容。
        /// </summary>
        private void InitializeComponent()
        {
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
            groupBoxRSASign.SuspendLayout();
            groupBoxRSAEncrypt.SuspendLayout();
            groupBoxRSAKeys.SuspendLayout();
            SuspendLayout();
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
            label2.Text = "密钥类型:";
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
            // RSATabControl
            // 
            AutoScaleDimensions = new SizeF(9F, 20F);
            AutoScaleMode = AutoScaleMode.Font;
            Controls.Add(groupBoxRSASign);
            Controls.Add(groupBoxRSAEncrypt);
            Controls.Add(groupBoxRSAKeys);
            Margin = new Padding(4);
            Name = "RSATabControl";
            Size = new Size(1278, 832);
            groupBoxRSASign.ResumeLayout(false);
            groupBoxRSASign.PerformLayout();
            groupBoxRSAEncrypt.ResumeLayout(false);
            groupBoxRSAEncrypt.PerformLayout();
            groupBoxRSAKeys.ResumeLayout(false);
            groupBoxRSAKeys.PerformLayout();
            ResumeLayout(false);
        }

        #endregion

        private GroupBox groupBoxRSASign;
        private ComboBox comboRSASignAlgmFormat;
        private Label label29;
        private ComboBox comboRSASignOutputFormat;
        private Label label28;
        private Label labelRSAVerifyResult;
        private Label label8;
        private TextBox textRSASignature;
        private Label label7;
        private TextBox textRSASignData;
        private Button btnRSAVerify;
        private Button btnRSASign;
        private GroupBox groupBoxRSAEncrypt;
        private ComboBox comboRSAEncryptOutputFormat;
        private Label label27;
        private Label label6;
        private TextBox textRSACipherText;
        private ComboBox comboRSAKeyPadding;
        private Label label5;
        private Label label25;
        private TextBox textRSAPlainText;
        private Button btnRSADecrypt;
        private Button btnRSAEncrypt;
        private GroupBox groupBoxRSAKeys;
        private ComboBox comboRSAKeyOutputFormat;
        private Label label26;
        private Button btnExportRSAKey;
        private Button btnImportRSAKey;
        private Label label4;
        private TextBox textRSAPrivateKey;
        private Label label3;
        private TextBox textRSAPublicKey;
        private Label label2;
        private ComboBox comboRSAKeyFormat;
        private Label label1;
        private ComboBox comboRSAKeySize;
        private Button btnGenerateRSAKey;
    }
}
