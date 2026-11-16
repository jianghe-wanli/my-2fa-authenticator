package com.f2a.authenticator.ui.screens.home

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import com.f2a.authenticator.data.model.AuthToken
import com.f2a.authenticator.data.model.Tag
import com.f2a.authenticator.ui.components.parseHexColor
import com.f2a.authenticator.ui.theme.Radius
import com.f2a.authenticator.ui.theme.Space
import com.f2a.authenticator.ui.theme.Touch
import com.f2a.authenticator.ui.theme.Type

@Composable
fun DeleteTagConfirmDialog(
    tag: Tag,
    onDismiss: () -> Unit,
    onConfirm: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("删除标签") },
        text = {
            Text("确认删除标签「${tag.name}」吗？已绑定此标签的账号将解除绑定，账号本身不会受到影响。")
        },
        confirmButton = {
            Button(
                onClick = onConfirm,
                colors = ButtonDefaults.buttonColors(
                    containerColor = MaterialTheme.colorScheme.error,
                    contentColor = MaterialTheme.colorScheme.onError
                )
            ) { Text("确认删除") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("取消") }
        }
    )
}

@Composable
fun CreateTagDialog(
    onDismiss: () -> Unit,
    onCreate: (name: String, colorHex: String) -> Unit
) {
    var newTagName by rememberSaveable { mutableStateOf("") }
    var selectedColorHex by rememberSaveable { mutableStateOf("#3B82F6") }
    val colorOptions = listOf("#3B82F6", "#10B981", "#F59E0B", "#EF4444", "#8B5CF6", "#EC4899", "#06B6D4")

    Dialog(onDismissRequest = onDismiss) {
        Card(
            shape = RoundedCornerShape(Radius.L),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            modifier = Modifier.padding(Space.L)
        ) {
            Column(modifier = Modifier.padding(Space.XL)) {
                Text("新建自定义标签", style = Type.TitleCard)
                Spacer(modifier = Modifier.height(Space.M))
                OutlinedTextField(
                    value = newTagName,
                    onValueChange = { newTagName = it },
                    label = { Text("标签名称 (如: 👑 主要账号, 🍼 小号)") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(Radius.S)
                )
                Spacer(modifier = Modifier.height(Space.ML))
                Text("选择颜色：", style = Type.BodyS, fontWeight = FontWeight.Bold)
                Spacer(modifier = Modifier.height(Space.HS))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    colorOptions.forEach { hex ->
                        Box(
                            modifier = Modifier
                                .size(28.dp)
                                .clip(CircleShape)
                                .background(parseHexColor(hex))
                                .border(
                                    width = if (selectedColorHex == hex) 2.dp else 0.dp,
                                    color = if (selectedColorHex == hex) MaterialTheme.colorScheme.onSurface else Color.Transparent,
                                    shape = CircleShape
                                )
                                .clickable { selectedColorHex = hex }
                        )
                    }
                }
                Spacer(modifier = Modifier.height(Space.XL))
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                    TextButton(
                        onClick = onDismiss,
                        modifier = Modifier.heightIn(min = Touch.MinTarget)
                    ) { Text("取消") }
                    Spacer(modifier = Modifier.width(Space.S))
                    Button(
                        onClick = {
                            if (newTagName.isNotBlank()) {
                                onCreate(newTagName.trim(), selectedColorHex)
                            }
                        },
                        enabled = newTagName.isNotBlank(),
                        shape = RoundedCornerShape(Radius.M),
                        modifier = Modifier.heightIn(min = Touch.MinTarget)
                    ) { Text("保存标签") }
                }
            }
        }
    }
}

@Composable
fun SoftDeleteTokenConfirmDialog(
    token: AuthToken,
    onDismiss: () -> Unit,
    onConfirm: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("移入回收站") },
        text = {
            Text("确认将「${token.issuer} · ${token.accountName}」移入回收站吗？凭据将在回收站保留 7 天，期间可在设置页恢复。")
        },
        confirmButton = {
            Button(
                onClick = onConfirm,
                colors = ButtonDefaults.buttonColors(
                    containerColor = MaterialTheme.colorScheme.error,
                    contentColor = MaterialTheme.colorScheme.onError
                )
            ) { Text("移入回收站") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("取消") }
        }
    )
}
