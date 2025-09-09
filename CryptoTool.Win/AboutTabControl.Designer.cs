namespace CryptoTool.Win
{
    partial class AboutTabControl : UserControl
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
            if (disposing)
            {
                components?.Dispose();
                _httpClient?.Dispose();
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
            groupBoxAppInfo = new GroupBox();
            labelAppName = new Label();
            textAppName = new TextBox();
            labelAppVersion = new Label();
            textAppVersion = new TextBox();
            labelAppAuthor = new Label();
            textAppAuthor = new TextBox();
            labelAppDescription = new Label();
            textAppDescription = new TextBox();
            labelAppRepository = new Label();
            linkAppRepository = new LinkLabel();
            labelAppLicense = new Label();
            textAppLicense = new TextBox();
            groupBoxUpdate = new GroupBox();
            labelCurrentVersion = new Label();
            textCurrentVersion = new TextBox();
            labelLatestVersion = new Label();
            textLatestVersion = new TextBox();
            labelUpdateStatus = new Label();
            textUpdateStatus = new TextBox();
            btnCheckUpdate = new Button();
            btnDownloadUpdate = new Button();
            progressUpdate = new ProgressBar();
            groupBoxSystemInfo = new GroupBox();
            labelOSInfo = new Label();
            textOSInfo = new TextBox();
            labelDotNetVersion = new Label();
            textDotNetVersion = new TextBox();
            labelAppPath = new Label();
            textAppPath = new TextBox();
            groupBoxAppInfo.SuspendLayout();
            groupBoxUpdate.SuspendLayout();
            groupBoxSystemInfo.SuspendLayout();
            SuspendLayout();
            // 
            // groupBoxAppInfo
            // 
            groupBoxAppInfo.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            groupBoxAppInfo.Controls.Add(labelAppName);
            groupBoxAppInfo.Controls.Add(textAppName);
            groupBoxAppInfo.Controls.Add(labelAppVersion);
            groupBoxAppInfo.Controls.Add(textAppVersion);
            groupBoxAppInfo.Controls.Add(labelAppAuthor);
            groupBoxAppInfo.Controls.Add(textAppAuthor);
            groupBoxAppInfo.Controls.Add(labelAppDescription);
            groupBoxAppInfo.Controls.Add(textAppDescription);
            groupBoxAppInfo.Controls.Add(labelAppRepository);
            groupBoxAppInfo.Controls.Add(linkAppRepository);
            groupBoxAppInfo.Controls.Add(labelAppLicense);
            groupBoxAppInfo.Controls.Add(textAppLicense);
            groupBoxAppInfo.Location = new Point(8, 6);
            groupBoxAppInfo.Margin = new Padding(4);
            groupBoxAppInfo.Name = "groupBoxAppInfo";
            groupBoxAppInfo.Padding = new Padding(4);
            groupBoxAppInfo.Size = new Size(1264, 220);
            groupBoxAppInfo.TabIndex = 0;
            groupBoxAppInfo.TabStop = false;
            groupBoxAppInfo.Text = "软件信息";
            // 
            // labelAppName
            // 
            labelAppName.AutoSize = true;
            labelAppName.Location = new Point(15, 31);
            labelAppName.Margin = new Padding(4, 0, 4, 0);
            labelAppName.Name = "labelAppName";
            labelAppName.Size = new Size(73, 20);
            labelAppName.TabIndex = 0;
            labelAppName.Text = "软件名称:";
            // 
            // textAppName
            // 
            textAppName.Location = new Point(100, 27);
            textAppName.Margin = new Padding(4);
            textAppName.Name = "textAppName";
            textAppName.ReadOnly = true;
            textAppName.Size = new Size(250, 27);
            textAppName.TabIndex = 1;
            // 
            // labelAppVersion
            // 
            labelAppVersion.AutoSize = true;
            labelAppVersion.Location = new Point(370, 31);
            labelAppVersion.Margin = new Padding(4, 0, 4, 0);
            labelAppVersion.Name = "labelAppVersion";
            labelAppVersion.Size = new Size(73, 20);
            labelAppVersion.TabIndex = 2;
            labelAppVersion.Text = "软件版本:";
            // 
            // textAppVersion
            // 
            textAppVersion.Location = new Point(450, 27);
            textAppVersion.Margin = new Padding(4);
            textAppVersion.Name = "textAppVersion";
            textAppVersion.ReadOnly = true;
            textAppVersion.Size = new Size(200, 27);
            textAppVersion.TabIndex = 3;
            // 
            // labelAppAuthor
            // 
            labelAppAuthor.AutoSize = true;
            labelAppAuthor.Location = new Point(15, 65);
            labelAppAuthor.Margin = new Padding(4, 0, 4, 0);
            labelAppAuthor.Name = "labelAppAuthor";
            labelAppAuthor.Size = new Size(73, 20);
            labelAppAuthor.TabIndex = 4;
            labelAppAuthor.Text = "软件作者:";
            // 
            // textAppAuthor
            // 
            textAppAuthor.Location = new Point(100, 62);
            textAppAuthor.Margin = new Padding(4);
            textAppAuthor.Name = "textAppAuthor";
            textAppAuthor.ReadOnly = true;
            textAppAuthor.Size = new Size(250, 27);
            textAppAuthor.TabIndex = 5;
            // 
            // labelAppDescription
            // 
            labelAppDescription.AutoSize = true;
            labelAppDescription.Location = new Point(15, 100);
            labelAppDescription.Margin = new Padding(4, 0, 4, 0);
            labelAppDescription.Name = "labelAppDescription";
            labelAppDescription.Size = new Size(73, 20);
            labelAppDescription.TabIndex = 6;
            labelAppDescription.Text = "软件描述:";
            // 
            // textAppDescription
            // 
            textAppDescription.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            textAppDescription.Location = new Point(100, 96);
            textAppDescription.Margin = new Padding(4);
            textAppDescription.Multiline = true;
            textAppDescription.Name = "textAppDescription";
            textAppDescription.ReadOnly = true;
            textAppDescription.ScrollBars = ScrollBars.Vertical;
            textAppDescription.Size = new Size(1150, 50);
            textAppDescription.TabIndex = 7;
            // 
            // labelAppRepository
            // 
            labelAppRepository.AutoSize = true;
            labelAppRepository.Location = new Point(15, 160);
            labelAppRepository.Margin = new Padding(4, 0, 4, 0);
            labelAppRepository.Name = "labelAppRepository";
            labelAppRepository.Size = new Size(73, 20);
            labelAppRepository.TabIndex = 8;
            labelAppRepository.Text = "代码仓库:";
            // 
            // linkAppRepository
            // 
            linkAppRepository.AutoSize = true;
            linkAppRepository.Location = new Point(100, 160);
            linkAppRepository.Margin = new Padding(4, 0, 4, 0);
            linkAppRepository.Name = "linkAppRepository";
            linkAppRepository.Size = new Size(0, 20);
            linkAppRepository.TabIndex = 9;
            linkAppRepository.LinkClicked += LinkAppRepository_LinkClicked;
            // 
            // labelAppLicense
            // 
            labelAppLicense.AutoSize = true;
            labelAppLicense.Location = new Point(15, 190);
            labelAppLicense.Margin = new Padding(4, 0, 4, 0);
            labelAppLicense.Name = "labelAppLicense";
            labelAppLicense.Size = new Size(73, 20);
            labelAppLicense.TabIndex = 10;
            labelAppLicense.Text = "软件许可:";
            // 
            // textAppLicense
            // 
            textAppLicense.Location = new Point(100, 186);
            textAppLicense.Margin = new Padding(4);
            textAppLicense.Name = "textAppLicense";
            textAppLicense.ReadOnly = true;
            textAppLicense.Size = new Size(250, 27);
            textAppLicense.TabIndex = 11;
            // 
            // groupBoxUpdate
            // 
            groupBoxUpdate.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            groupBoxUpdate.Controls.Add(labelCurrentVersion);
            groupBoxUpdate.Controls.Add(textCurrentVersion);
            groupBoxUpdate.Controls.Add(labelLatestVersion);
            groupBoxUpdate.Controls.Add(textLatestVersion);
            groupBoxUpdate.Controls.Add(labelUpdateStatus);
            groupBoxUpdate.Controls.Add(textUpdateStatus);
            groupBoxUpdate.Controls.Add(btnCheckUpdate);
            groupBoxUpdate.Controls.Add(btnDownloadUpdate);
            groupBoxUpdate.Controls.Add(progressUpdate);
            groupBoxUpdate.Location = new Point(8, 235);
            groupBoxUpdate.Margin = new Padding(4);
            groupBoxUpdate.Name = "groupBoxUpdate";
            groupBoxUpdate.Padding = new Padding(4);
            groupBoxUpdate.Size = new Size(1264, 150);
            groupBoxUpdate.TabIndex = 1;
            groupBoxUpdate.TabStop = false;
            groupBoxUpdate.Text = "自动更新";
            // 
            // labelCurrentVersion
            // 
            labelCurrentVersion.AutoSize = true;
            labelCurrentVersion.Location = new Point(15, 31);
            labelCurrentVersion.Margin = new Padding(4, 0, 4, 0);
            labelCurrentVersion.Name = "labelCurrentVersion";
            labelCurrentVersion.Size = new Size(73, 20);
            labelCurrentVersion.TabIndex = 0;
            labelCurrentVersion.Text = "当前版本:";
            // 
            // textCurrentVersion
            // 
            textCurrentVersion.Location = new Point(100, 27);
            textCurrentVersion.Margin = new Padding(4);
            textCurrentVersion.Name = "textCurrentVersion";
            textCurrentVersion.ReadOnly = true;
            textCurrentVersion.Size = new Size(200, 27);
            textCurrentVersion.TabIndex = 1;
            // 
            // labelLatestVersion
            // 
            labelLatestVersion.AutoSize = true;
            labelLatestVersion.Location = new Point(320, 31);
            labelLatestVersion.Margin = new Padding(4, 0, 4, 0);
            labelLatestVersion.Name = "labelLatestVersion";
            labelLatestVersion.Size = new Size(73, 20);
            labelLatestVersion.TabIndex = 2;
            labelLatestVersion.Text = "最新版本:";
            // 
            // textLatestVersion
            // 
            textLatestVersion.Location = new Point(400, 27);
            textLatestVersion.Margin = new Padding(4);
            textLatestVersion.Name = "textLatestVersion";
            textLatestVersion.ReadOnly = true;
            textLatestVersion.Size = new Size(200, 27);
            textLatestVersion.TabIndex = 3;
            // 
            // labelUpdateStatus
            // 
            labelUpdateStatus.AutoSize = true;
            labelUpdateStatus.Location = new Point(15, 65);
            labelUpdateStatus.Margin = new Padding(4, 0, 4, 0);
            labelUpdateStatus.Name = "labelUpdateStatus";
            labelUpdateStatus.Size = new Size(73, 20);
            labelUpdateStatus.TabIndex = 4;
            labelUpdateStatus.Text = "更新状态:";
            // 
            // textUpdateStatus
            // 
            textUpdateStatus.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            textUpdateStatus.Location = new Point(100, 62);
            textUpdateStatus.Margin = new Padding(4);
            textUpdateStatus.Name = "textUpdateStatus";
            textUpdateStatus.ReadOnly = true;
            textUpdateStatus.Size = new Size(1150, 27);
            textUpdateStatus.TabIndex = 5;
            // 
            // btnCheckUpdate
            // 
            btnCheckUpdate.Location = new Point(620, 25);
            btnCheckUpdate.Margin = new Padding(3, 4, 3, 4);
            btnCheckUpdate.Name = "btnCheckUpdate";
            btnCheckUpdate.Size = new Size(120, 31);
            btnCheckUpdate.TabIndex = 6;
            btnCheckUpdate.Text = "检查更新";
            btnCheckUpdate.UseVisualStyleBackColor = true;
            btnCheckUpdate.Click += BtnCheckUpdate_Click;
            // 
            // btnDownloadUpdate
            // 
            btnDownloadUpdate.Enabled = false;
            btnDownloadUpdate.Location = new Point(760, 25);
            btnDownloadUpdate.Margin = new Padding(3, 4, 3, 4);
            btnDownloadUpdate.Name = "btnDownloadUpdate";
            btnDownloadUpdate.Size = new Size(120, 31);
            btnDownloadUpdate.TabIndex = 7;
            btnDownloadUpdate.Text = "下载更新";
            btnDownloadUpdate.UseVisualStyleBackColor = true;
            btnDownloadUpdate.Click += BtnDownloadUpdate_Click;
            // 
            // progressUpdate
            // 
            progressUpdate.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            progressUpdate.Location = new Point(15, 100);
            progressUpdate.Margin = new Padding(4);
            progressUpdate.Name = "progressUpdate";
            progressUpdate.Size = new Size(1235, 30);
            progressUpdate.TabIndex = 8;
            progressUpdate.Visible = false;
            // 
            // groupBoxSystemInfo
            // 
            groupBoxSystemInfo.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            groupBoxSystemInfo.Controls.Add(labelOSInfo);
            groupBoxSystemInfo.Controls.Add(textOSInfo);
            groupBoxSystemInfo.Controls.Add(labelDotNetVersion);
            groupBoxSystemInfo.Controls.Add(textDotNetVersion);
            groupBoxSystemInfo.Controls.Add(labelAppPath);
            groupBoxSystemInfo.Controls.Add(textAppPath);
            groupBoxSystemInfo.Location = new Point(8, 395);
            groupBoxSystemInfo.Margin = new Padding(4);
            groupBoxSystemInfo.Name = "groupBoxSystemInfo";
            groupBoxSystemInfo.Padding = new Padding(4);
            groupBoxSystemInfo.Size = new Size(1264, 120);
            groupBoxSystemInfo.TabIndex = 2;
            groupBoxSystemInfo.TabStop = false;
            groupBoxSystemInfo.Text = "系统信息";
            // 
            // labelOSInfo
            // 
            labelOSInfo.AutoSize = true;
            labelOSInfo.Location = new Point(15, 31);
            labelOSInfo.Margin = new Padding(4, 0, 4, 0);
            labelOSInfo.Name = "labelOSInfo";
            labelOSInfo.Size = new Size(73, 20);
            labelOSInfo.TabIndex = 0;
            labelOSInfo.Text = "操作系统:";
            // 
            // textOSInfo
            // 
            textOSInfo.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            textOSInfo.Location = new Point(100, 27);
            textOSInfo.Margin = new Padding(4);
            textOSInfo.Name = "textOSInfo";
            textOSInfo.ReadOnly = true;
            textOSInfo.Size = new Size(1150, 27);
            textOSInfo.TabIndex = 1;
            // 
            // labelDotNetVersion
            // 
            labelDotNetVersion.AutoSize = true;
            labelDotNetVersion.Location = new Point(15, 65);
            labelDotNetVersion.Margin = new Padding(4, 0, 4, 0);
            labelDotNetVersion.Name = "labelDotNetVersion";
            labelDotNetVersion.Size = new Size(101, 20);
            labelDotNetVersion.TabIndex = 2;
            labelDotNetVersion.Text = ".NET框架版本:";
            // 
            // textDotNetVersion
            // 
            textDotNetVersion.Location = new Point(125, 62);
            textDotNetVersion.Margin = new Padding(4);
            textDotNetVersion.Name = "textDotNetVersion";
            textDotNetVersion.ReadOnly = true;
            textDotNetVersion.Size = new Size(300, 27);
            textDotNetVersion.TabIndex = 3;
            // 
            // labelAppPath
            // 
            labelAppPath.AutoSize = true;
            labelAppPath.Location = new Point(450, 65);
            labelAppPath.Margin = new Padding(4, 0, 4, 0);
            labelAppPath.Name = "labelAppPath";
            labelAppPath.Size = new Size(73, 20);
            labelAppPath.TabIndex = 4;
            labelAppPath.Text = "安装路径:";
            // 
            // textAppPath
            // 
            textAppPath.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            textAppPath.Location = new Point(530, 62);
            textAppPath.Margin = new Padding(4);
            textAppPath.Name = "textAppPath";
            textAppPath.ReadOnly = true;
            textAppPath.Size = new Size(720, 27);
            textAppPath.TabIndex = 5;
            // 
            // AboutTabControl
            // 
            AutoScaleDimensions = new SizeF(9F, 20F);
            AutoScaleMode = AutoScaleMode.Font;
            Controls.Add(groupBoxAppInfo);
            Controls.Add(groupBoxUpdate);
            Controls.Add(groupBoxSystemInfo);
            Margin = new Padding(3, 4, 3, 4);
            Name = "AboutTabControl";
            Size = new Size(1278, 920);
            groupBoxAppInfo.ResumeLayout(false);
            groupBoxAppInfo.PerformLayout();
            groupBoxUpdate.ResumeLayout(false);
            groupBoxUpdate.PerformLayout();
            groupBoxSystemInfo.ResumeLayout(false);
            groupBoxSystemInfo.PerformLayout();
            ResumeLayout(false);
        }

        #endregion

        private GroupBox groupBoxAppInfo;
        private Label labelAppName;
        private TextBox textAppName;
        private Label labelAppVersion;
        private TextBox textAppVersion;
        private Label labelAppAuthor;
        private TextBox textAppAuthor;
        private Label labelAppDescription;
        private TextBox textAppDescription;
        private Label labelAppRepository;
        private LinkLabel linkAppRepository;
        private Label labelAppLicense;
        private TextBox textAppLicense;
        private GroupBox groupBoxUpdate;
        private Label labelCurrentVersion;
        private TextBox textCurrentVersion;
        private Label labelLatestVersion;
        private TextBox textLatestVersion;
        private Label labelUpdateStatus;
        private TextBox textUpdateStatus;
        private Button btnCheckUpdate;
        private Button btnDownloadUpdate;
        private ProgressBar progressUpdate;
        private GroupBox groupBoxSystemInfo;
        private Label labelOSInfo;
        private TextBox textOSInfo;
        private Label labelDotNetVersion;
        private TextBox textDotNetVersion;
        private Label labelAppPath;
        private TextBox textAppPath;
    }
}