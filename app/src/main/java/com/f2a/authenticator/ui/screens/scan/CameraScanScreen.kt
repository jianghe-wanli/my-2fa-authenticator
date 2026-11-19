package com.f2a.authenticator.ui.screens.scan

import android.Manifest
import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
import android.content.Intent
import android.content.pm.PackageManager
import android.hardware.camera2.CaptureRequest
import android.net.Uri
import android.provider.Settings
import android.util.Size
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.PickVisualMediaRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.annotation.OptIn
import androidx.camera.camera2.interop.Camera2Interop
import androidx.camera.camera2.interop.ExperimentalCamera2Interop
import androidx.camera.core.Camera
import androidx.camera.core.CameraSelector
import androidx.camera.core.FocusMeteringAction
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.Preview
import androidx.camera.core.resolutionselector.AspectRatioStrategy
import androidx.camera.core.resolutionselector.ResolutionSelector
import androidx.camera.core.resolutionselector.ResolutionStrategy
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.FlashOff
import androidx.compose.material.icons.filled.FlashOn
import androidx.compose.material.icons.filled.Keyboard
import androidx.compose.material.icons.filled.PhotoLibrary
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.core.view.WindowCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.f2a.authenticator.data.model.AuthToken
import com.f2a.authenticator.data.model.Tag
import com.f2a.authenticator.data.model.Workspace
import com.f2a.authenticator.totp.GoogleMigrationDecoder
import com.f2a.authenticator.totp.OtpUriParser
import com.f2a.authenticator.totp.WorkspaceInferenceEngine
import com.f2a.authenticator.ui.theme.CobaltPrimaryDark
import com.f2a.authenticator.ui.theme.IconSize
import com.f2a.authenticator.ui.theme.LocalSemanticColors
import com.f2a.authenticator.ui.theme.NavyBg
import com.f2a.authenticator.ui.theme.NavySurface
import com.f2a.authenticator.ui.theme.Radius
import com.f2a.authenticator.ui.theme.Space
import com.f2a.authenticator.ui.theme.Touch
import com.f2a.authenticator.ui.theme.Type
import com.f2a.authenticator.ui.utils.QrBitmapRenderer
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

@kotlin.OptIn(ExperimentalMaterial3Api::class)
@OptIn(ExperimentalCamera2Interop::class)
@Composable
fun CameraScanScreen(
    currentActiveWorkspaceId: String,
    allWorkspaces: List<Workspace>,
    allTags: List<Tag> = emptyList(),
    onSuppressNextBackgroundLock: () -> Unit,
    onBack: () -> Unit,
    onManualInputClick: () -> Unit,
    onTokenScanned: (AuthToken) -> Unit,
    onBatchTokensScanned: (List<AuthToken>, batchNotice: String?) -> Unit
) {
    val context = LocalContext.current
    val view = LocalView.current
    val semantic = LocalSemanticColors.current
    val lifecycleOwner = LocalLifecycleOwner.current
    val snackbarHostState = remember { SnackbarHostState() }
    val uiScope = rememberCoroutineScope()

    // 深色扫描页强制保持状态栏白色图标，退出时还原主题原状
    DisposableEffect(view, semantic.isDark) {
        val window = (context as? Activity)?.window
        val controller = window?.let { WindowCompat.getInsetsController(it, view) }
        controller?.isAppearanceLightStatusBars = false
        onDispose {
            controller?.isAppearanceLightStatusBars = !semantic.isDark
        }
    }

    val isDisposedRef = remember { AtomicBoolean(false) }

    val handleBack: () -> Unit = {
        isDisposedRef.set(true)
        onBack()
    }
    val handleManualInput: () -> Unit = {
        isDisposedRef.set(true)
        onManualInputClick()
    }

    BackHandler(onBack = handleBack)

    var hasCameraPermission by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED
        )
    }
    var hasRequestedPermission by rememberSaveable { mutableStateOf(false) }
    val validTagIds = remember(allTags) { allTags.map { it.id }.toHashSet() }

    val showScanMessage: (String) -> Unit = { msg ->
        uiScope.launch {
            snackbarHostState.currentSnackbarData?.dismiss()
            snackbarHostState.showSnackbar(msg)
        }
    }

    val isProcessingQr = remember { AtomicBoolean(false) }

    val handleDecodedText: (String) -> Unit = { rawText ->
        val clean = rawText.trim()
        if (GoogleMigrationDecoder.isGoogleMigrationUri(clean)) {
            val batch = GoogleMigrationDecoder.decodeBatch(clean, currentActiveWorkspaceId)
            if (batch.tokens.isNotEmpty()) {
                val enriched = batch.tokens.map { tok ->
                    val suggestion = WorkspaceInferenceEngine.infer(
                        issuer = tok.issuer,
                        accountName = tok.accountName,
                        tenantEnv = tok.tenantEnv,
                        currentActiveWorkspaceId = currentActiveWorkspaceId,
                        allWorkspaces = allWorkspaces
                    )
                    val filteredSuggested = suggestion.suggestedTagIds.filter {
                        validTagIds.isEmpty() || it in validTagIds
                    }
                    val mergedTags = (tok.tagIds + filteredSuggested).distinct()
                    tok.copy(workspaceId = suggestion.workspaceId, tagIds = mergedTags)
                }
                val hint = if (batch.batchSize > 1) {
                    "已识别第 ${batch.batchIndex + 1}/${batch.batchSize} 批迁移码（共 ${enriched.size} 个凭据）"
                } else null
                onBatchTokensScanned(enriched, hint)
            } else {
                isProcessingQr.set(false)
                showScanMessage("无法解析 Google 迁移码，请检查二维码是否完整")
            }
        } else {
            when (val res = OtpUriParser.parseDetailed(clean)) {
                is OtpUriParser.OtpParseResult.Ok -> {
                    val suggestion = WorkspaceInferenceEngine.infer(
                        issuer = res.token.issuer,
                        accountName = res.token.accountName,
                        tenantEnv = res.token.tenantEnv,
                        currentActiveWorkspaceId = currentActiveWorkspaceId,
                        allWorkspaces = allWorkspaces
                    )
                    val filteredSuggested = suggestion.suggestedTagIds.filter {
                        validTagIds.isEmpty() || it in validTagIds
                    }
                    val mergedTags = (res.token.tagIds + filteredSuggested).distinct()
                    onTokenScanned(res.token.copy(workspaceId = suggestion.workspaceId, tagIds = mergedTags))
                }
                is OtpUriParser.OtpParseResult.Error -> {
                    isProcessingQr.set(false)
                    showScanMessage("未识别出有效 2FA 密钥：${res.reason}")
                }
            }
        }
    }
    val latestHandleDecodedText by rememberUpdatedState(handleDecodedText)

    val permissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission()
    ) { granted ->
        hasCameraPermission = granted
        hasRequestedPermission = true
        if (!granted) showScanMessage("需要相机权限以扫描 2FA 二维码")
    }

    val galleryLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.PickVisualMedia()
    ) { uri ->
        if (uri != null) {
            uiScope.launch {
                val decoded = withContext(Dispatchers.Default) {
                    QrBitmapRenderer.decodeQrFromUri(context, uri)
                }
                if (!decoded.isNullOrBlank()) {
                    if (isProcessingQr.compareAndSet(false, true)) {
                        handleDecodedText(decoded)
                    }
                } else {
                    showScanMessage("图片中未识别出有效的二维码")
                }
            }
        }
    }

    val launchGalleryPicker: () -> Unit = {
        onSuppressNextBackgroundLock()
        try {
            galleryLauncher.launch(PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageOnly))
        } catch (_: Exception) {
            showScanMessage("未找到可用系统相册选择器，请改用相机扫码或手动输入")
        }
    }

    LaunchedEffect(Unit) {
        if (!hasCameraPermission && !hasRequestedPermission) {
            permissionLauncher.launch(Manifest.permission.CAMERA)
        }
    }

    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME) {
                hasCameraPermission = ContextCompat.checkSelfPermission(
                    context, Manifest.permission.CAMERA
                ) == PackageManager.PERMISSION_GRANTED
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    var isTorchOn by remember { mutableStateOf(false) }
    var cameraRef by remember { mutableStateOf<Camera?>(null) }
    var previewViewRef by remember { mutableStateOf<PreviewView?>(null) }
    val cameraProviderRef = remember { mutableStateOf<ProcessCameraProvider?>(null) }
    val imageAnalysisRef = remember { mutableStateOf<ImageAnalysis?>(null) }
    val frameAnalyzer = remember {
        QrFrameAnalyzer(isProcessingQr = isProcessingQr) { qrText ->
            previewViewRef?.post {
                if (!isDisposedRef.get() && isProcessingQr.compareAndSet(false, true)) {
                    latestHandleDecodedText(qrText)
                }
            }
        }
    }
    val cameraExecutor = remember { Executors.newSingleThreadExecutor() }

    DisposableEffect(Unit) {
        onDispose {
            isDisposedRef.set(true)
            try {
                imageAnalysisRef.value?.clearAnalyzer()
                cameraProviderRef.value?.unbindAll()
            } catch (_: Exception) {}
            frameAnalyzer.release()
            cameraExecutor.shutdownNow()
        }
    }

    Scaffold(
        containerColor = NavyBg,
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = { Text("扫描 QR 码", color = Color.White, style = Type.TitleSection) },
                navigationIcon = {
                    IconButton(onClick = handleBack, modifier = Modifier.size(Touch.MinTarget)) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "返回", tint = Color.White, modifier = Modifier.size(IconSize.L))
                    }
                },
                actions = {
                    IconButton(
                        onClick = {
                            val cam = cameraRef
                            if (cam != null && cam.cameraInfo.hasFlashUnit()) {
                                val nextTorch = !isTorchOn
                                try {
                                    cam.cameraControl.enableTorch(nextTorch)
                                    isTorchOn = nextTorch
                                } catch (_: Exception) {}
                            }
                        },
                        modifier = Modifier
                            .size(Touch.MinTarget)
                            .semantics { stateDescription = if (isTorchOn) "关闭手电筒" else "打开手电筒" }
                    ) {
                        Icon(
                            imageVector = if (isTorchOn) Icons.Default.FlashOn else Icons.Default.FlashOff,
                            contentDescription = if (isTorchOn) "关闭手电筒" else "打开手电筒",
                            tint = if (isTorchOn) CobaltPrimaryDark else Color.White,
                            modifier = Modifier.size(IconSize.L)
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = NavyBg.copy(alpha = 0.72f))
            )
        }
    ) { innerPadding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .pointerInput(hasCameraPermission) {
                    if (hasCameraPermission) {
                        detectTapGestures { offset ->
                            val cam = cameraRef
                            val pv = previewViewRef
                            if (cam != null && pv != null) {
                                try {
                                    val point = pv.meteringPointFactory.createPoint(offset.x, offset.y)
                                    val action = FocusMeteringAction.Builder(
                                        point,
                                        FocusMeteringAction.FLAG_AF or FocusMeteringAction.FLAG_AE
                                    ).setAutoCancelDuration(3, TimeUnit.SECONDS).build()
                                    cam.cameraControl.startFocusAndMetering(action)
                                } catch (_: Exception) {}
                            }
                        }
                    }
                }
        ) {
            if (hasCameraPermission) {
                AndroidView(
                    modifier = Modifier.fillMaxSize(),
                    factory = { ctx ->
                        val previewView = PreviewView(ctx).apply {
                            scaleType = PreviewView.ScaleType.FILL_CENTER
                            implementationMode = PreviewView.ImplementationMode.COMPATIBLE
                        }
                        previewViewRef = previewView
                        val cameraProviderFuture = ProcessCameraProvider.getInstance(ctx)
                        cameraProviderFuture.addListener({
                            if (isDisposedRef.get()) return@addListener
                            try {
                                val cameraProvider = cameraProviderFuture.get()
                                if (isDisposedRef.get()) return@addListener
                                cameraProviderRef.value = cameraProvider

                                val previewSelector = ResolutionSelector.Builder()
                                    .setAspectRatioStrategy(AspectRatioStrategy.RATIO_16_9_FALLBACK_AUTO_STRATEGY)
                                    .setResolutionStrategy(ResolutionStrategy(Size(1920, 1080), ResolutionStrategy.FALLBACK_RULE_CLOSEST_HIGHER_THEN_LOWER))
                                    .build()
                                val analysisSelector = ResolutionSelector.Builder()
                                    .setAspectRatioStrategy(AspectRatioStrategy.RATIO_16_9_FALLBACK_AUTO_STRATEGY)
                                    .setResolutionStrategy(ResolutionStrategy(Size(1280, 720), ResolutionStrategy.FALLBACK_RULE_CLOSEST_HIGHER_THEN_LOWER))
                                    .build()

                                val previewBuilder = Preview.Builder().setResolutionSelector(previewSelector)
                                val analysisBuilder = ImageAnalysis.Builder()
                                    .setResolutionSelector(analysisSelector)
                                    .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                                    .setOutputImageFormat(ImageAnalysis.OUTPUT_IMAGE_FORMAT_YUV_420_888)

                                Camera2Interop.Extender(previewBuilder)
                                    .setCaptureRequestOption(CaptureRequest.CONTROL_AF_MODE, CaptureRequest.CONTROL_AF_MODE_CONTINUOUS_PICTURE)
                                    .setCaptureRequestOption(CaptureRequest.CONTROL_AE_MODE, CaptureRequest.CONTROL_AE_MODE_ON)
                                Camera2Interop.Extender(analysisBuilder)
                                    .setCaptureRequestOption(CaptureRequest.CONTROL_AF_MODE, CaptureRequest.CONTROL_AF_MODE_CONTINUOUS_PICTURE)
                                    .setCaptureRequestOption(CaptureRequest.CONTROL_AE_MODE, CaptureRequest.CONTROL_AE_MODE_ON)

                                val preview = previewBuilder.build().also { it.surfaceProvider = previewView.surfaceProvider }
                                val imageAnalysis = analysisBuilder.build().also { it.setAnalyzer(cameraExecutor, frameAnalyzer) }
                                imageAnalysisRef.value = imageAnalysis

                                val selector = when {
                                    cameraProvider.hasCamera(CameraSelector.DEFAULT_BACK_CAMERA) -> CameraSelector.DEFAULT_BACK_CAMERA
                                    cameraProvider.hasCamera(CameraSelector.DEFAULT_FRONT_CAMERA) -> CameraSelector.DEFAULT_FRONT_CAMERA
                                    else -> {
                                        showScanMessage("未检测到可用摄像头，请从相册选图或手动输入")
                                        return@addListener
                                    }
                                }

                                cameraProvider.unbindAll()
                                val camera = cameraProvider.bindToLifecycle(
                                    lifecycleOwner,
                                    selector,
                                    preview,
                                    imageAnalysis
                                )
                                cameraRef = camera
                                val maxZoom = camera.cameraInfo.zoomState.value?.maxZoomRatio ?: 1f
                                if (maxZoom >= 1.25f) {
                                    camera.cameraControl.setZoomRatio(1.25f)
                                }
                                previewView.post {
                                    if (!isDisposedRef.get()) {
                                        startCenterFocus(previewView, camera)
                                    }
                                }
                            } catch (_: Exception) {
                                showScanMessage("相机启动失败，请检查权限或使用相册选图")
                            }
                        }, ContextCompat.getMainExecutor(ctx))
                        previewView
                    }
                )

                ScanOverlayLayer()

                Box(
                    modifier = Modifier
                        .align(Alignment.TopCenter)
                        .padding(top = Space.XXL, start = Space.XXL, end = Space.XXL)
                ) {
                    Text(
                        text = "将 2FA 二维码或 Google 迁移码置于框内",
                        color = Color.White.copy(alpha = 0.92f),
                        style = Type.BodyS,
                        modifier = Modifier
                            .clip(RoundedCornerShape(Radius.Full))
                            .background(NavySurface.copy(alpha = 0.78f))
                            .border(1.dp, Color.White.copy(alpha = 0.14f), RoundedCornerShape(Radius.Full))
                            .padding(horizontal = Space.L, vertical = Space.HS)
                    )
                }

                // 底部深蓝半透明悬浮工具栏
                Row(
                    modifier = Modifier
                        .align(Alignment.BottomCenter)
                        .padding(horizontal = Space.XL, vertical = Space.XXL)
                        .clip(RoundedCornerShape(Radius.XL))
                        .background(NavySurface.copy(alpha = 0.85f))
                        .border(1.dp, Color.White.copy(alpha = 0.14f), RoundedCornerShape(Radius.XL))
                        .padding(Space.M)
                        .fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(Space.M)
                ) {
                    OutlinedButton(
                        onClick = launchGalleryPicker,
                        colors = ButtonDefaults.outlinedButtonColors(
                            containerColor = NavyBg.copy(alpha = 0.5f),
                            contentColor = Color.White
                        ),
                        shape = RoundedCornerShape(Radius.M),
                        modifier = Modifier
                            .weight(1f)
                            .heightIn(min = Touch.MinTarget)
                    ) {
                        Icon(Icons.Default.PhotoLibrary, contentDescription = null, modifier = Modifier.size(IconSize.S))
                        Spacer(modifier = Modifier.width(Space.XS))
                        Text("相册选图", style = Type.BodyM, fontWeight = FontWeight.SemiBold)
                    }

                    Button(
                        onClick = handleManualInput,
                        colors = ButtonDefaults.buttonColors(
                            containerColor = CobaltPrimaryDark,
                            contentColor = Color(0xFF061836)
                        ),
                        shape = RoundedCornerShape(Radius.M),
                        modifier = Modifier
                            .weight(1f)
                            .heightIn(min = Touch.MinTarget)
                    ) {
                        Icon(Icons.Default.Keyboard, contentDescription = null, modifier = Modifier.size(IconSize.S))
                        Spacer(modifier = Modifier.width(Space.XS))
                        Text("手动输入", style = Type.BodyM, fontWeight = FontWeight.SemiBold)
                    }
                }
            } else {
                val activity = context.findComponentActivity()
                val canAskAgain = hasRequestedPermission && activity != null &&
                    ActivityCompat.shouldShowRequestPermissionRationale(activity, Manifest.permission.CAMERA)
                CameraPermissionGuide(
                    hasRequestedPermission = hasRequestedPermission,
                    canAskAgain = canAskAgain,
                    onRequest = { permissionLauncher.launch(Manifest.permission.CAMERA) },
                    onOpenSettings = {
                        try {
                            val intent = Intent(
                                Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                                Uri.fromParts("package", context.packageName, null)
                            ).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                            context.startActivity(intent)
                        } catch (_: Exception) {
                            showScanMessage("无法打开系统设置，请手动前往应用权限开启相机")
                        }
                    },
                    onPickFromGallery = launchGalleryPicker,
                    onManualInput = handleManualInput,
                    modifier = Modifier.align(Alignment.Center)
                )
            }
        }
    }
}

private tailrec fun Context.findComponentActivity(): ComponentActivity? = when (this) {
    is ComponentActivity -> this
    is ContextWrapper -> baseContext.findComponentActivity()
    else -> null
}

private fun startCenterFocus(previewView: PreviewView, camera: Camera) {
    val width = previewView.width.toFloat()
    val height = previewView.height.toFloat()
    if (width <= 0f || height <= 0f) return
    try {
        val centerPoint = previewView.meteringPointFactory.createPoint(width / 2f, height / 2f)
        val action = FocusMeteringAction.Builder(
            centerPoint,
            FocusMeteringAction.FLAG_AF or FocusMeteringAction.FLAG_AE
        ).setAutoCancelDuration(3, TimeUnit.SECONDS).build()
        camera.cameraControl.startFocusAndMetering(action)
    } catch (_: Exception) {}
}
