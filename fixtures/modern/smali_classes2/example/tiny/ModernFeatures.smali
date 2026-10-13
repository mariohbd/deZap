.class public Lexample/tiny/ModernFeatures;
.super Ljava/lang/Object;

# Original example: execute a DEX038 polymorphic invocation on Android API26+.
.method public static label()Ljava/lang/String;
    .locals 3
    const-class v0, Ljava/lang/String;
    const-string v1, "Offline fixture 038"
    invoke-static {v0, v1}, Ljava/lang/invoke/MethodHandles;->constant(Ljava/lang/Class;Ljava/lang/Object;)Ljava/lang/invoke/MethodHandle;
    move-result-object v2
    invoke-polymorphic {v2}, Ljava/lang/invoke/MethodHandle;->invokeExact([Ljava/lang/Object;)Ljava/lang/Object;, ()Ljava/lang/String;
    move-result-object v0
    return-object v0
.end method
