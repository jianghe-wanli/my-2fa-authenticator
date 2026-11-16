package com.f2a.authenticator.totp

import com.f2a.authenticator.data.model.Tag
import com.f2a.authenticator.data.model.Workspace
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class WorkspaceInferenceEngineTest {

    private val workspaces = listOf(
        Workspace.DEFAULT_PERSONAL,
        Workspace.DEFAULT_WORK,
        Workspace.DEFAULT_DEVOPS
    )

    @Test
    fun activeWorkspace_notAll_isPreservedDirectly() {
        val suggestion = WorkspaceInferenceEngine.infer(
            issuer = "AWS",
            accountName = "root@prod.com",
            tenantEnv = "Prod",
            currentActiveWorkspaceId = Workspace.DEFAULT_PERSONAL.id,
            allWorkspaces = workspaces
        )
        assertEquals(Workspace.DEFAULT_PERSONAL.id, suggestion.workspaceId)
        assertTrue(Tag.TAG_ASSET.id in suggestion.suggestedTagIds)
    }

    @Test
    fun allWorkspace_infersDevopsAndWorkAndPersonal() {
        val awsProd = WorkspaceInferenceEngine.infer(
            issuer = "Amazon Web Services",
            accountName = "admin@company.com",
            tenantEnv = "Prod-亚太主集群",
            currentActiveWorkspaceId = "all",
            allWorkspaces = workspaces
        )
        assertEquals(Workspace.DEFAULT_DEVOPS.id, awsProd.workspaceId)
        assertTrue(Tag.TAG_ASSET.id in awsProd.suggestedTagIds)

        val ghEnterprise = WorkspaceInferenceEngine.infer(
            issuer = "GitHub Enterprise",
            accountName = "lead@corp.io",
            tenantEnv = "Dev-沙箱",
            currentActiveWorkspaceId = "all",
            allWorkspaces = workspaces
        )
        assertEquals(Workspace.DEFAULT_WORK.id, ghEnterprise.workspaceId)
        assertTrue(Tag.TAG_DEV.id in ghEnterprise.suggestedTagIds)
    }

    @Test
    fun wordBoundary_preventsFalsePositivesOnSteamworksFrameworkIsraelClawsIncorporate() {
        val falsePositiveIssuers = listOf(
            "Steamworks",
            "Framework Laptop",
            "Upwork",
            "Israel Post",
            "Claws Mail",
            "Incorporate Hub"
        )
        for (issuer in falsePositiveIssuers) {
            val wsId = WorkspaceInferenceEngine.inferWorkspaceId(
                issuer = issuer,
                accountName = "user@example.com",
                currentActiveWorkspaceId = "all",
                allWorkspaces = workspaces
            )
            assertEquals("Issuer '$issuer' should fall back to personal", Workspace.DEFAULT_PERSONAL.id, wsId)
        }
    }
}
