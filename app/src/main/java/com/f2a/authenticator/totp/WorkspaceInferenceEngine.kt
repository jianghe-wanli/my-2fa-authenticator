package com.f2a.authenticator.totp

import com.f2a.authenticator.data.model.Tag
import com.f2a.authenticator.data.model.Workspace
import java.util.Locale

/**
 * 智能工作区与标签自适应推断引擎
 */
object WorkspaceInferenceEngine {

    data class InferenceSuggestion(
        val workspaceId: String,
        val suggestedTagIds: List<String>
    )

    // 使用 ASCII 字母数字边界，防止 Steamworks/Framework/Upwork/Israel/Claws/Incorporate 误匹配
    private val DEVOPS_WORD_REGEX = Regex(
        """(?<![a-z0-9])(aws|amazon|aliyun|alibaba|tencent|cloudflare|azure|digitalocean|linode|kubernetes|k8s|docker|dockerhub|sre|devops|gcp|terraform|ansible|prometheus|grafana|vultr|hetzner|huawei|huaweicloud|oracle|oci|vercel|netlify|heroku|render|railway|supabase|sentry|datadog|tailscale|wireguard|proxmox|synology|unifi|ssh|bastion|jumpserver|vault|consul|harbor|jenkins|argocd|npm|pypi)(?![a-z0-9])""",
        RegexOption.IGNORE_CASE
    )
    private val DEVOPS_CJK_KEYWORDS = listOf("运维", "阿里云", "腾讯云", "华为云", "百度云", "七牛", "集群", "服务器", "堡垒机", "群晖")

    private val WORK_WORD_REGEX = Regex(
        """(?<![a-z0-9])(corp|company|work|jira|confluence|slack|feishu|lark|dingtalk|wecom|gitlab|bitbucket|enterprise|okta|intranet|microsoft|office365|m365|teams|zoom|notion|linear|figma|asana|trello|zendesk|salesforce|hubspot|vpn|sso|ldap)(?![a-z0-9])""",
        RegexOption.IGNORE_CASE
    )
    private val WORK_CJK_KEYWORDS = listOf("企业", "公司", "办公", "飞书", "钉钉", "企微", "跳板机", "内网")

    private val ASSET_TAG_WORD_REGEX = Regex(
        """(?<![a-z0-9])(prod|production|prd|master|root|admin|bank|pay|finance|wallet|exchange|binance|coinbase|okx|bybit|kraken|bitget|metamask|ledger|trezor|stripe|paypal|alipay|wechatpay|icloud|apple|1password|bitwarden|proton|registrar|namecheap|godaddy|namesilo|porkbun)(?![a-z0-9])""",
        RegexOption.IGNORE_CASE
    )
    private val ASSET_TAG_CJK_KEYWORDS = listOf("生产", "主集群", "支付", "核心", "资产", "银行", "交易所", "钱包", "域名", "密码库")

    private val DEV_TAG_WORD_REGEX = Regex(
        """(?<![a-z0-9])(dev|test|stage|staging|sandbox|qa|uat|local)(?![a-z0-9])""",
        RegexOption.IGNORE_CASE
    )
    private val DEV_TAG_CJK_KEYWORDS = listOf("开发", "测试", "沙箱", "预发", "灰度")

    private val MAIN_TAG_WORD_REGEX = Regex(
        """(?<![a-z0-9])(primary|main)(?![a-z0-9])""",
        RegexOption.IGNORE_CASE
    )
    private val MAIN_TAG_CJK_KEYWORDS = listOf("主力", "主要", "主号")

    private val SUB_TAG_WORD_REGEX = Regex(
        """(?<![a-z0-9])(sub|alt|minor|backup)(?![a-z0-9])""",
        RegexOption.IGNORE_CASE
    )
    private val SUB_TAG_CJK_KEYWORDS = listOf("小号", "辅助", "备用")

    /**
     * 综合 issuer、accountName、tenantEnv 与当前工作区上下文推断目标工作区及建议标签。
     */
    fun infer(
        issuer: String,
        accountName: String,
        tenantEnv: String,
        currentActiveWorkspaceId: String,
        allWorkspaces: List<Workspace>
    ): InferenceSuggestion {
        val text = "$issuer $accountName $tenantEnv".lowercase(Locale.US)

        val workspaceId = resolveWorkspaceId(
            text = text,
            currentActiveWorkspaceId = currentActiveWorkspaceId,
            allWorkspaces = allWorkspaces
        )

        val tags = LinkedHashSet<String>()
        if (ASSET_TAG_WORD_REGEX.containsMatchIn(text) || ASSET_TAG_CJK_KEYWORDS.any { text.contains(it) }) {
            tags.add(Tag.TAG_ASSET.id)
        }
        if (DEV_TAG_WORD_REGEX.containsMatchIn(text) || DEV_TAG_CJK_KEYWORDS.any { text.contains(it) }) {
            tags.add(Tag.TAG_DEV.id)
        }
        if (MAIN_TAG_WORD_REGEX.containsMatchIn(text) || MAIN_TAG_CJK_KEYWORDS.any { text.contains(it) }) {
            tags.add(Tag.TAG_MAIN.id)
        }
        if (SUB_TAG_WORD_REGEX.containsMatchIn(text) || SUB_TAG_CJK_KEYWORDS.any { text.contains(it) }) {
            tags.add(Tag.TAG_SUB.id)
        }

        return InferenceSuggestion(
            workspaceId = workspaceId,
            suggestedTagIds = tags.toList()
        )
    }

    /**
     * 扫码/导入时智能推断归属工作区：
     * 1. 优先使用用户当前停留的工作区（只要不是 "all"）
     * 2. 若在 "all" 下导入，优先匹配用户自定义工作区名称，其次按服务商与账号信息匹配默认属性工作区
     */
    fun inferWorkspaceId(
        issuer: String,
        accountName: String,
        currentActiveWorkspaceId: String,
        allWorkspaces: List<Workspace>
    ): String {
        return infer(
            issuer = issuer,
            accountName = accountName,
            tenantEnv = "",
            currentActiveWorkspaceId = currentActiveWorkspaceId,
            allWorkspaces = allWorkspaces
        ).workspaceId
    }

    private fun resolveWorkspaceId(
        text: String,
        currentActiveWorkspaceId: String,
        allWorkspaces: List<Workspace>
    ): String {
        if (currentActiveWorkspaceId.isNotBlank() && currentActiveWorkspaceId != "all") {
            val exists = allWorkspaces.any { it.id == currentActiveWorkspaceId }
            if (exists) return currentActiveWorkspaceId
        }

        val defaultIds = setOf(
            Workspace.DEFAULT_PERSONAL.id,
            Workspace.DEFAULT_WORK.id,
            Workspace.DEFAULT_DEVOPS.id
        )
        val customMatch = allWorkspaces.firstOrNull { ws ->
            if (ws.id in defaultIds) return@firstOrNull false
            val wsName = ws.name.trim().lowercase(Locale.US)
            wsName.length >= 2 && text.contains(wsName)
        }
        if (customMatch != null) return customMatch.id

        if (DEVOPS_WORD_REGEX.containsMatchIn(text) || DEVOPS_CJK_KEYWORDS.any { text.contains(it) }) {
            val devopsWs = allWorkspaces.firstOrNull {
                it.id == Workspace.DEFAULT_DEVOPS.id ||
                    it.iconName.equals("Terminal", ignoreCase = true) ||
                    it.name.contains("运维")
            }
            if (devopsWs != null) return devopsWs.id
        }

        if (WORK_WORD_REGEX.containsMatchIn(text) || WORK_CJK_KEYWORDS.any { text.contains(it) }) {
            val workWs = allWorkspaces.firstOrNull {
                it.id == Workspace.DEFAULT_WORK.id ||
                    it.iconName.equals("BusinessCenter", ignoreCase = true) ||
                    it.name.contains("工作")
            }
            if (workWs != null) return workWs.id
        }

        val personalWs = allWorkspaces.firstOrNull {
            it.id == Workspace.DEFAULT_PERSONAL.id ||
                it.iconName.equals("Person", ignoreCase = true) ||
                it.name.contains("个人")
        }
        return personalWs?.id ?: (allWorkspaces.firstOrNull()?.id ?: Workspace.DEFAULT_PERSONAL.id)
    }
}
