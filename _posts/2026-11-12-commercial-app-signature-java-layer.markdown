---
layout: post
title: "逆向某商业 App：摸清请求签名的完整 Java 层调用链"
date: 2026-11-12
tags: [Android逆向, jadx, 签名分析]
---

从一个国内头部生活服务类 App v12.x（91MB，5万+类）出发，纯静态分析追完请求签名参数在 Java 层的完整调用链，直到撞上 native 边界。记录全过程踩的坑和用到的手法。

> ⚠️ 本文仅用于安全研究与学习交流，请勿用于任何违法违规用途。

## 0. 环境

| 工具 | 用途 |
|---|---|
| unzip | APK 解包侦察 |
| jadx 1.5.0 | dex → Java 反编译 |
| PowerShell / Git Bash | 命令行 |
| 已 root 的 Pixel | 后续动态分析用（本文静态为主） |

## 1. 侦察：先判断有没有壳

解包后看两样东西：DEX 大小 + SO 列表。

```bash
unzip app.apk -d apk_extracted/
ls -lh apk_extracted/*.dex
ls -lh apk_extracted/lib/arm64-v8a/
```

结果：

- 12 个 dex 全部 4~11MB 正常范围 → **无整体加固**，不用脱壳，直接反编译
- 某防护 SO 2433KB → **防护核心**（下称 guard.so）

### 怎么一眼锁定防护 SO？

三个信号叠加：

1. **命名**：SO 名包含公司缩写 + `guard`（防护），命名即自曝
2. **大小**：签名功能几百 KB 足够写，2.4MB 说明塞了 OLLVM 混淆和反调试——"简单功能异常臃肿"
3. **公开知识**：该签名参数由哪个 SO 生成是圈内公开信息

对比 v8 引擎(10MB)、地图渲染(7.5MB) 这些"功能本来就复杂"的库，防护 SO 的膨胀才可疑。

## 2. 五万个类怎么过滤？

jadx 反编译完成后有 50227 个类，不可能挨个看。方法论就一句：**线索驱动搜索，不做无目的浏览**。

jadx-gui 关键快捷键：

- `Ctrl+N`：类名搜索
- `Ctrl+Shift+F`：全文搜索
- 右键 Find Usage：追引用

我从抓包时见过的签名参数名（请求头里那个自定义的 sig 字段）入手：

```
50,000 类 → 全文搜签名参数名 → 5 个类 → 追调用链 → 锁定 ShellBridge
```

取舍原则：**追生成者，不看使用者**。业务包里出现的签名参数都是把它塞进请求头的调用方，要找的是安全 SDK 包（guard 包）下的生成逻辑。

## 3. 逐层穿透调用链

### 3.1 第一层：签名注入的拦截器

```java
HashMap hashMap2 = new HashMap();
IIVTQYOSF.IIVTQYOSF(context, uri, bArr, str2, str4, hashMap2, hashMap);
```

注意这个模式：签名不走 return，而是**输出参数**——把空 Map 传进去，函数执行完签名被塞进来（Java 传对象 = 传引用）。

### 3.2 坑一：PatchProxy 热更新壳

该 App 每个方法都被 Robust 热更新框架（开源项目）包裹：

```java
if (PatchProxy.isSupport(...)) {
    return PatchProxy.accessDispatch(...);  // 死路，99%不走
} else {
    // ★ 真逻辑永远在 else 里
}
```

看到 PatchProxy 直接跳 else。

### 3.3 坑二：同名方法有 8 个重载，找哪个？

混淆类里同名方法一大堆。判断方法：**看调用处传了几个参数什么类型，找签名完全匹配的版本**。

```
调用: IIVTQYOSF(context, uri, true, bArr, str, str2, map, str3, map2)
目标: IIVTQYOSF(Context, URI, boolean, byte[], String, String, Map, String, Map) ← 参数对上
```

另一个技巧：方法体只有一行转发调用的 = 包装层，继续深入。

### 3.4 坑三：jadx 反编译失败

追到核心方法时：

```java
/* Method dump skipped, instructions count: 470 */
throw new UnsupportedOperationException("Method not decompiled");
```

**为什么失败？** 编译是单向有损的：源码的循环变 goto、变量名变寄存器、嵌套结构变跳转表。反编译器靠"猜"还原，470 条指令 + 多层 try-catch + 匿名内部类，猜到矛盾就放弃。不排除厂方故意构造让反编译器崩溃的字节码——这本身就是一种防护。

**解决：**

```bash
jadx --show-bad-code --single-class <核心类的完整类名> -d out app.apk
```

成功拿到完整逻辑。

### 3.5 核心方法还原结果

```java
private static URI IIVTQYOSF(Context context, URI uri, boolean z, byte[] bArr, ...) {
    // ① 打包请求信息
    CandyBaseMaterial material = new CandyBaseMaterial() {
        getHost()        → uri.getHost()
        getPostContent() → bArr        // POST body
        getUserAgent()   → UA
    };

    // ② ★ 进入 SO 层
    Object[] main3 = ShellBridge.main3(120, new Object[]{material});
    Map map3 = (Map) main3[0];

    // ③ 签名塞回输出 Map（= 外层的 hashMap2）
    map.putAll(map3);
}
```

**命令 ID 120 = 签名生成。**

### 3.6 ShellBridge：Java 的尽头

```java
public class ShellBridge {
    private static native Object[] main(int i, Object[] objArr);  // ← native！

    public static Object[] main3(int i, Object[] objArr) {
        return main(i, objArr);   // Java 尽头 → JNI → guard.so
    }
}
```

`native` 关键字 + 入口类里的 `System.loadLibrary(...)`，证据链闭合。

### 3.7 彩蛋：双向通信机制

ShellBridge 里还有个 `main2`，方向相反——**SO 回调 Java**：

```java
public static Object main2(int i, Object[] objArr) {
    switch (i) {
        case 1: return "6.7.15";             // SO 问：SDK 版本？
        case 2: return MTGuard.sPackageName;  // SO 问：包名？
        case 3: return MTGuard.dataDir;      // SO 问：数据目录？
    }
}
```

这套防护是双向桥：Java 调 SO 算签名（main3），SO 执行时反向向 Java 收集环境信息（main2）。这直接给后续 unidbg 模拟定了难点：**必须把所有 main2 回调伪造完整，否则 SO 返回错误签名**。

## 4. 命令 ID 速查表

所有安全功能走 `main3(命令ID, 参数)` 单一入口：

| ID | 功能 |
|---|---|
| 1 | 初始化 native |
| 15 | Root 检测 |
| 16 | 模拟器检测 |
| 18 | 代理检测 |
| 19 | 沙箱检测 |
| 20 | Hook 检测 |
| 21 | 调试检测 |
| 30/31 | 加解密 |
| 103 | 设备指纹 |
| **120** | **签名生成** |

## 5. 完整调用链（成果）

```
HTTP 请求
  → NBridge.requestSignatureForBabelV4()
    → 拦截器 getRequestSignature()
      → IIVTQYOSF.IIVTQYOSF(context, uri, body, ...)
        → 封装 CandyBaseMaterial (url/body/UA/method)
        → ShellBridge.main3(120, material)    ← ★ Java 层尽头
          → main() [native]
            → guard.so 内部
              ← 返回 Map{ sig: "签名" }
```

## 6. 方法论沉淀

1. **线索驱动**：从已知字符串（签名参数名）、SO 名出发搜索
2. **数据流倒推**：不问"该看哪个函数"，问"结果从哪来"——签名在 Map 里 → putAll(map3) → map3 来自 main3 返回值 → 顺藤摸瓜
3. **噪音过滤**：PatchProxy 跳 else、日志统计跳过、一行转发的包装层继续深入
4. **工具失效的 backup**：jadx 失败用 `--show-bad-code`，再不行换 JEB 或看 smali
5. **认清边界**：追到 native 方法即 Java 层终点，转战 SO 层

## 7. 下一步

1. Frida 动态 Hook `ShellBridge.main`，看真实运行时进出 SO 的参数
2. IDA 分析 guard.so 的 JNI_OnLoad 与命令分发器（找 ID=120 的处理函数）
3. unidbg 黑盒模拟，重点伪造 main2 回调链

---

*声明：本文仅用于安全研究与学习交流，目标为国内某商业 App，已做匿名化处理。请勿用于任何违法违规用途。*
