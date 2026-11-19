# 极盾 2FA (My2FAApp)

一款完全离线、隐私优先的 Android 双重认证（2FA）保险库应用，基于 **Kotlin + Jetpack Compose + Material 3 + CameraX + ZXing + Android KeyStore** 构建，无任何网络权限与后台遥测。

---

## 核心特性

### 1. 标准协议与全兼容迁移
- **OTP 算法内核**：严格遵循 RFC 6238 (TOTP) 与 RFC 4226 (HOTP)，支持 HMAC-SHA1 / SHA256 / SHA512、6/8 位数字、10~300 秒自定义周期，以及 **Steam Guard 5 字符令牌**。
- **二维码与多生态协议导入**：
  - `CameraX` 原生实时扫描 + **相册选图静态解码**（支持透明背景 QR PNG 与高分辨率大图缩放解码）。
  - 兼容标准 `otpauth://totp|hotp|steam/...`（含多行批量文本）、裸 Base32 密钥输入、`otpauth-migration://offline?data=...` **Google Authenticator 批量迁移协议**，以及 **Aegis / 2FAS / Bitwarden** 未加密 JSON 导入（自动拆分多批与智能工作区/标签推断）。
- **单条与批量迁移导出**：详情页支持单凭据标准 `otpauth://` 二维码导出；二次 PIN 鉴权后按分包生成标准 `otpauth-migration://` 二维码与链接，自动跳过不可导出的损坏/Steam 令牌并提示周期兼容说明。

### 2. 多工作区与防拥挤交互
- **工作区横向分页 + 平台手风琴折叠**：按工作区（`全部` / `个人生活` / `工作主业` / `运维多租户` 等）组织，默认全部折叠收起，支持「记忆上次」「仅展开置顶」「默认全折叠」三种折叠策略及一键全部展开/折叠。
- **快跳索引与多维筛选**：顶部工作区 Tab、动态标签过滤、平台快跳胶囊、多维排序（置顶+数量 / A-Z / 最近使用）与实时全文搜索。
- **7 天软删除回收站**：误删凭据先入回收站保留 7 天，随时恢复或彻底销毁，超期解锁时自动清理。

### 3. 硬件级离线安全体系
- **Android KeyStore 硬件加密**：所有 2FA Secret 经硬件 TEE / StrongBox 托管的 AES-256-GCM 主密钥加密存盘（`vault_document.json`），严格延迟解密，未解锁前明文永不进内存。
- **独立主密码 + 生物识别 + 胁迫销毁 + 离线安全体检**：
  - 6 位独立保险库密码（`PBKDF2WithHmacSHA256`，210,000 次迭代 + 随机盐 + 常量时间比对，兼容旧版 100K 哈希）。
  - 基于系统单调时钟 `elapsedRealtime()` 的防篡改冷却锁定（设备重启仍延续剩余冷却）。
  - 支持 `BiometricPrompt` 强生物识别解锁、**胁迫密码（静默销毁并伪装空库）**、多次错密自动物理自毁，以及设置页长按 3 秒三步确认物理自毁。
  - 内置离线「安全体检中心」（重复密钥、损坏/弱熵凭据、未设胁迫码、备份超期提醒等）。
- **隐私与前后台防窥**：
  - 支持列表/详情**隐私防窥遮罩**（默认打码 + 盲点直接复制 + 10 秒临时显码），锁屏与敏感弹窗强制开启 `FLAG_SECURE` 及防点击劫持保护。
  - 后台超时自动锁定（支持立即 / 30 秒 / 1 分钟 / 5 分钟 / 关闭），并对系统相册/SAF 选择器提供安全短窗豁免。
  - 剪贴板敏感标记（Android 13+ `EXTRA_IS_SENSITIVE`）+ 限时自动清除倒计时浮条与一键立即抹除。
- **端到端加密灾备（`.jdf2`）**：使用 `PBKDF2WithHmacSHA256`（210,000 次迭代）+ AES-256-GCM 零知识加密导出/导入文件与密文，兼容 legacy v1 备份读取。

---

## 工程结构

```text
app/src/main/java/com/f2a/authenticator/
├── MainActivity.kt              # Single-Activity 宿主与安全壳（FLAG_SECURE + 生物识别）
├── My2FAApplication.kt          # AppContainer 初始化与后台锁监听注册
├── crypto/                      # KeyStoreManager, SecretCipher, BackupManager (JDF2 v2)
├── data/
│   ├── local/                   # TokenVaultRepository, TokenRepository, VaultPreferencesStore
│   └── model/                   # AuthToken, Workspace, Tag, VaultPreferences (Schema v2)
├── di/                          # 手工轻量依赖注入容器 (AppContainer)
├── security/                    # SecurityLockManager, BiometricHelper, BackgroundLockMonitor, VaultHealthAnalyzer, Clock
├── totp/                        # OtpEngine, OtpUriParser, GoogleMigrationDecoder/Encoder, ExternalImportParser, WorkspaceInferenceEngine
├── ui/
│   ├── components/              # OtpTicker(0 重组时钟隔离), IssuerAccordionCard, AccountItemRow 等
│   ├── screens/                 # lock, home, detail, scan(CameraX+ZXing), settings, dialogs
│   ├── state/ & viewmodel/      # 单向数据流 UiState 与独立 ViewModel
│   └── theme/                   # Precision Deep-Blue Vault 深浅色语义色表与 Design Tokens
└── utils/                       # SecureClipboard, ClipboardGuard
```

---

## 编译与测试

### 环境要求
- **JDK**: 17
- **Android SDK**: `compileSdk = 35`, `minSdk = 26`, `targetSdk = 35`
- **Gradle**: 8.14.4（已内置 Wrapper，本地无额外在线仓库时 `zxing-core-3.5.4.jar` 位于 `app/libs/`）

### 本地构建与单元测试

```bash
# 运行全部 JVM 单元测试（78 项用例）
./gradlew testDebugUnitTest

# 构建 Debug APK
./gradlew assembleDebug
```

Windows PowerShell 下执行：

```powershell
.\gradlew.bat testDebugUnitTest assembleDebug
```

### 构建签名版 Release APK

在项目根目录创建 `local.properties`（已被 `.gitignore` 忽略，**严禁提交私钥与密码**）或注入环境变量：

```properties
sdk.dir=C:\\Path\\To\\Android\\Sdk
RELEASE_STORE_FILE=your-release-keystore.jks
RELEASE_STORE_PASSWORD=your_store_password
RELEASE_KEY_ALIAS=your_key_alias
RELEASE_KEY_PASSWORD=your_key_password
```

然后执行：

```bash
./gradlew assembleRelease
```

---

## 隐私声明

本应用在 `AndroidManifest.xml` 中**不申请 `INTERNET` 网络权限**，且禁用系统云备份（`allowBackup="false"`），全部密钥生成、存储、加密与二维码识别均 100% 在设备本地完成。
