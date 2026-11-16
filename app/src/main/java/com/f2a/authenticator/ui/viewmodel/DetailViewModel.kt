package com.f2a.authenticator.ui.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.f2a.authenticator.data.local.TokenVaultRepository
import com.f2a.authenticator.data.model.AuthToken
import com.f2a.authenticator.data.model.Tag
import com.f2a.authenticator.data.model.Workspace
import com.f2a.authenticator.security.SecurityLockManager
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch

class DetailViewModel(
    private val tokenRepository: TokenVaultRepository,
    private val securityManager: SecurityLockManager
) : ViewModel() {

    val allTags: StateFlow<List<Tag>> = tokenRepository.tags
    val allWorkspaces: StateFlow<List<Workspace>> = tokenRepository.workspaces

    fun observeToken(tokenId: String): Flow<AuthToken?> =
        tokenRepository.tokens.map { list -> list.firstOrNull { it.id == tokenId } }

    fun currentTokenSnapshot(tokenId: String): AuthToken? =
        tokenRepository.tokens.value.firstOrNull { it.id == tokenId }

    fun getClipboardClearSeconds(): Int = securityManager.getClipboardClearSeconds()

    fun updateToken(token: AuthToken) {
        viewModelScope.launch {
            tokenRepository.updateToken(token)
        }
    }

    fun advanceHotp(token: AuthToken) {
        viewModelScope.launch {
            tokenRepository.advanceHotp(token.id)
        }
    }

    fun recordTokenUsed(tokenId: String) {
        viewModelScope.launch {
            tokenRepository.recordTokenUsed(tokenId)
        }
    }

    fun softDeleteToken(tokenId: String, onDeleted: () -> Unit) {
        viewModelScope.launch {
            tokenRepository.softDeleteToken(tokenId)
            onDeleted()
        }
    }

    class Factory(
        private val tokenRepository: TokenVaultRepository,
        private val securityManager: SecurityLockManager
    ) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            return DetailViewModel(tokenRepository, securityManager) as T
        }
    }
}
