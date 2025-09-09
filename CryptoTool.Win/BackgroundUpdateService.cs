using System;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using Octokit;

namespace CryptoTool.Win
{
    /// <summary>
    /// 后台版本检测服务
    /// </summary>
    public class BackgroundUpdateService
    {
        #region 事件定义

        /// <summary>
        /// 发现新版本事件
        /// </summary>
        public event Action<Release>? NewVersionFound;

        /// <summary>
        /// 检测状态更新事件
        /// </summary>
        public event Action<string>? StatusUpdated;

        #endregion

        #region 私有字段

        private readonly GitHubClient _gitHubClient;
        private readonly string _repositoryOwner = "jinjupeng";
        private readonly string _repositoryName = "CryptoTool";
        private readonly System.Threading.Timer _timer;
        private readonly SemaphoreSlim _semaphore;
        private bool _disposed = false;

        #endregion

        #region 构造函数

        public BackgroundUpdateService()
        {
            _gitHubClient = new GitHubClient(new ProductHeaderValue("CryptoTool"));
            _semaphore = new SemaphoreSlim(1, 1);
            
            // 创建定时器，但不立即启动
            _timer = new System.Threading.Timer(async _ => await CheckForUpdatesAsync(), null, Timeout.Infinite, Timeout.Infinite);
        }

        #endregion

        #region 公共方法

        /// <summary>
        /// 启动后台检测服务
        /// </summary>
        /// <param name="initialDelay">初始延迟时间（毫秒），默认5秒</param>
        /// <param name="interval">检测间隔时间（毫秒），默认2小时</param>
        public void Start(int initialDelay = 5000, int interval = 7200000) // 默认2小时检测一次
        {
            if (_disposed) return;

            StatusUpdated?.Invoke("后台更新检测服务已启动");
            _timer.Change(initialDelay, interval);
        }

        /// <summary>
        /// 停止后台检测服务
        /// </summary>
        public void Stop()
        {
            if (_disposed) return;

            _timer.Change(Timeout.Infinite, Timeout.Infinite);
            StatusUpdated?.Invoke("后台更新检测服务已停止");
        }

        /// <summary>
        /// 手动触发版本检测
        /// </summary>
        /// <returns></returns>
        public async Task ManualCheckAsync()
        {
            if (_disposed) return;

            await CheckForUpdatesAsync();
        }

        #endregion

        #region 私有方法

        /// <summary>
        /// 异步检查更新
        /// </summary>
        private async Task CheckForUpdatesAsync()
        {
            if (_disposed || !await _semaphore.WaitAsync(100))
                return;

            try
            {
                StatusUpdated?.Invoke("正在后台检测更新...");

                var latestRelease = await _gitHubClient.Repository.Release.GetLatest(_repositoryOwner, _repositoryName);
                
                var currentVersion = Assembly.GetExecutingAssembly().GetName().Version;
                var latestVersionString = latestRelease.TagName.TrimStart('v');
                
                if (Version.TryParse(latestVersionString, out var latestVersion) && currentVersion != null)
                {
                    var comparison = currentVersion.CompareTo(latestVersion);
                    if (comparison < 0)
                    {
                        // 发现新版本
                        StatusUpdated?.Invoke($"发现新版本 {latestVersion}");
                        NewVersionFound?.Invoke(latestRelease);
                        return;
                    }
                    else if (comparison == 0)
                    {
                        StatusUpdated?.Invoke("当前版本是最新版本");
                    }
                    else
                    {
                        StatusUpdated?.Invoke("当前版本高于最新发布版本");
                    }
                }
                else
                {
                    StatusUpdated?.Invoke("版本比较失败");
                }
            }
            catch (RateLimitExceededException)
            {
                StatusUpdated?.Invoke("GitHub API 请求限制，将稍后重试");
            }
            catch (NotFoundException)
            {
                StatusUpdated?.Invoke("未找到软件仓库");
            }
            catch (Exception ex)
            {
                StatusUpdated?.Invoke($"后台检测更新失败: {ex.Message}");
            }
            finally
            {
                _semaphore.Release();
            }
        }

        #endregion

        #region IDisposable 实现

        public void Dispose()
        {
            if (_disposed) return;

            _disposed = true;
            _timer?.Dispose();
            _semaphore?.Dispose();
            
            StatusUpdated?.Invoke("后台更新检测服务已释放");
        }

        #endregion
    }
}