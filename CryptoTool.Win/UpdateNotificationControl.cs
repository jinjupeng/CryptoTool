using System;
using System.Drawing;
using System.Windows.Forms;

namespace CryptoTool.Win
{
    /// <summary>
    /// ������ʾ�ؼ�����ʾ�ڴ������Ͻ�
    /// </summary>
    public partial class UpdateNotificationControl : UserControl
    {
        #region �¼�����

        /// <summary>
        /// ���°�ť����¼�
        /// </summary>
        public event EventHandler? UpdateClicked;

        /// <summary>
        /// �رհ�ť����¼�
        /// </summary>
        public event EventHandler? CloseClicked;

        #endregion

        #region ˽���ֶ�

        private Label lblMessage;
        private Button btnUpdate;
        private Button btnClose;
        private Panel mainPanel;

        #endregion

        #region ����

        /// <summary>
        /// ���û��ȡ��ʾ��Ϣ
        /// </summary>
        public string Message
        {
            get => lblMessage?.Text ?? string.Empty;
            set
            {
                if (lblMessage != null)
                {
                    lblMessage.Text = value;
                }
            }
        }

        #endregion

        #region ���캯��

        public UpdateNotificationControl()
        {
            InitializeComponent();
            SetStyle(ControlStyles.SupportsTransparentBackColor, true);
        }

        #endregion

        #region ��ʼ������

        private void InitializeComponent()
        {
            this.SuspendLayout();

            // �����
            mainPanel = new Panel
            {
                BackColor = Color.FromArgb(220, 53, 69), // ��ɫ����
                BorderStyle = BorderStyle.None,
                Size = new Size(300, 60),
                Location = new Point(0, 0)
            };

            // ��Ϣ��ǩ
            lblMessage = new Label
            {
                Text = "�����°汾�ɸ���",
                ForeColor = Color.White,
                Font = new Font("΢���ź�", 9F, FontStyle.Regular),
                AutoSize = false,
                Size = new Size(180, 20),
                Location = new Point(10, 8),
                TextAlign = ContentAlignment.MiddleLeft
            };

            // ���°�ť
            btnUpdate = new Button
            {
                Text = "����",
                BackColor = Color.FromArgb(255, 255, 255, 30), // ��͸����ɫ
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("΢���ź�", 8F, FontStyle.Regular),
                Size = new Size(50, 25),
                Location = new Point(200, 8),
                Cursor = Cursors.Hand
            };
            btnUpdate.FlatAppearance.BorderSize = 1;
            btnUpdate.FlatAppearance.BorderColor = Color.White;
            btnUpdate.FlatAppearance.MouseOverBackColor = Color.FromArgb(255, 255, 255, 50);
            btnUpdate.Click += BtnUpdate_Click;

            // �رհ�ť
            btnClose = new Button
            {
                Text = "��",
                BackColor = Color.Transparent,
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("΢���ź�", 10F, FontStyle.Bold),
                Size = new Size(25, 25),
                Location = new Point(260, 8),
                Cursor = Cursors.Hand
            };
            btnClose.FlatAppearance.BorderSize = 0;
            btnClose.FlatAppearance.MouseOverBackColor = Color.FromArgb(255, 255, 255, 50);
            btnClose.Click += BtnClose_Click;

            // ��ӿؼ��������
            mainPanel.Controls.Add(lblMessage);
            mainPanel.Controls.Add(btnUpdate);
            mainPanel.Controls.Add(btnClose);

            // ���ÿؼ�����
            this.BackColor = Color.Transparent;
            this.Size = new Size(300, 60);
            this.Controls.Add(mainPanel);

            // ����Բ��Ч��
            SetRoundedCorners();

            this.ResumeLayout(false);
        }

        /// <summary>
        /// ����Բ��Ч��
        /// </summary>
        private void SetRoundedCorners()
        {
            var path = new System.Drawing.Drawing2D.GraphicsPath();
            var radius = 8;
            var rect = new Rectangle(0, 0, mainPanel.Width, mainPanel.Height);

            path.AddArc(rect.X, rect.Y, radius * 2, radius * 2, 180, 90);
            path.AddArc(rect.Right - radius * 2, rect.Y, radius * 2, radius * 2, 270, 90);
            path.AddArc(rect.Right - radius * 2, rect.Bottom - radius * 2, radius * 2, radius * 2, 0, 90);
            path.AddArc(rect.X, rect.Bottom - radius * 2, radius * 2, radius * 2, 90, 90);
            path.CloseFigure();

            mainPanel.Region = new Region(path);
        }

        #endregion

        #region �¼�������

        private void BtnUpdate_Click(object? sender, EventArgs e)
        {
            UpdateClicked?.Invoke(this, EventArgs.Empty);
        }

        private void BtnClose_Click(object? sender, EventArgs e)
        {
            CloseClicked?.Invoke(this, EventArgs.Empty);
        }

        #endregion

        #region ��������

        /// <summary>
        /// ��ʾ������ʾ��������Ч����
        /// </summary>
        public void ShowNotification()
        {
            this.Visible = true;
            this.BringToFront();

            // ���붯��Ч��
            var timer = new System.Windows.Forms.Timer { Interval = 30 };
            var opacity = 0.0;
            timer.Tick += (s, e) =>
            {
                opacity += 0.1;
                if (opacity >= 1.0)
                {
                    opacity = 1.0;
                    timer.Stop();
                    timer.Dispose();
                }
                this.BackColor = Color.FromArgb((int)(opacity * 255), this.BackColor.R, this.BackColor.G, this.BackColor.B);
            };
            timer.Start();
        }

        /// <summary>
        /// ���ظ�����ʾ��������Ч����
        /// </summary>
        public void HideNotification()
        {
            // ��������Ч��
            var timer = new System.Windows.Forms.Timer { Interval = 30 };
            var opacity = 1.0;
            timer.Tick += (s, e) =>
            {
                opacity -= 0.1;
                if (opacity <= 0)
                {
                    opacity = 0;
                    this.Visible = false;
                    timer.Stop();
                    timer.Dispose();
                }
                this.BackColor = Color.FromArgb((int)(opacity * 255), this.BackColor.R, this.BackColor.G, this.BackColor.B);
            };
            timer.Start();
        }

        #endregion
    }
}