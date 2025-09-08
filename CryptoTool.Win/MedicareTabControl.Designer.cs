namespace CryptoTool.Win
{
    partial class MedicareTabControl : UserControl
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
            groupBoxMedicareParams.SuspendLayout();
            groupBoxMedicareKeys.SuspendLayout();
            groupBoxMedicareAction.SuspendLayout();
            SuspendLayout();
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
            groupBoxMedicareAction.Size = new Size(1264, 450);
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
            textMedicareDecData.Size = new Size(1234, 60);
            textMedicareDecData.TabIndex = 14;
            // 
            // MedicareTabControl
            // 
            AutoScaleDimensions = new SizeF(9F, 20F);
            AutoScaleMode = AutoScaleMode.Font;
            Controls.Add(groupBoxMedicareParams);
            Controls.Add(groupBoxMedicareKeys);
            Controls.Add(groupBoxMedicareAction);
            Margin = new Padding(3, 4, 3, 4);
            Name = "MedicareTabControl";
            Size = new Size(1278, 920);
            groupBoxMedicareParams.ResumeLayout(false);
            groupBoxMedicareParams.PerformLayout();
            groupBoxMedicareKeys.ResumeLayout(false);
            groupBoxMedicareKeys.PerformLayout();
            groupBoxMedicareAction.ResumeLayout(false);
            groupBoxMedicareAction.PerformLayout();
            ResumeLayout(false);
        }

        #endregion

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
        private Button btnGenerateMedicareSM4Key;
        private Label labelMedicareSM4Key;
        private TextBox textMedicareSM4Key;
        private Button btnGenerateMedicareKey;
        private Button btnImportMedicareKey;
        private Button btnExportMedicareKey;
        private Label labelMedicarePublicKey;
        private TextBox textMedicarePublicKey;
        private Label labelMedicarePrivateKey;
        private TextBox textMedicarePrivateKey;
        private GroupBox groupBoxMedicareAction;
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
    }
}