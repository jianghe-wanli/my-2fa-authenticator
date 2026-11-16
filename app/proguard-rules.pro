-keepattributes *Annotation*
-keepattributes Signature
-keepattributes InnerClasses
-keepattributes EnclosingMethod

# Gson 反射序列化的数据模型（BackupManager 已迁出 data.model，可正常参与 R8 混淆）
-keep class com.f2a.authenticator.data.model.** { *; }
-keep class com.google.gson.reflect.TypeToken { *; }
-keep class * extends com.google.gson.reflect.TypeToken

# 仅保留数据模型层枚举，避免全局 enum 阻止 R8 裁剪
-keepclassmembers enum com.f2a.authenticator.data.model.** {
    <fields>;
    public static **[] values();
    public static ** valueOf(java.lang.String);
}

# Release 剥离非错误日志，防止信息泄露
-assumenosideeffects class android.util.Log {
    public static boolean isLoggable(java.lang.String, int);
    public static int v(...);
    public static int d(...);
    public static int i(...);
}
