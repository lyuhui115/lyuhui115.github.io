---
layout: post
title: "Android 逆向实战：从 APK 到协议级复现"
date: 2026-09-12
tags: [Android逆向, Frida, 协议分析]
---

最近拿一个国产 App（哆点，网吧上网认证平台）完整走了一遍逆向流程：从 APK 到脱离客户端独立通信。记录一下全过程，可复现。

> ⚠️ 本文仅用于学习研究，所有测试均针对自己控制的账号，请勿用于非法用途。

## 0. 环境

| 工具 | 用途 |
|---|---|
| jadx 1.3.2 | 反编译 dex → Java |
| androguard | 解析 Manifest / 组件 / 权限 |
| Frida + 已 root 的 Pixel 3 | 动态 hook |
| Python (pycryptodome) | 算法复现、独立客户端 |

## 1. 信息收集

```bash
file app.apk                       # Android package, with classes.dex
unzip -l app.apk | grep -E "\.so"  # 看 native 库
```

判断加固：lib/ 下只有地图/统计 SDK，无 `libjiagu.so`、`libDexHelper.so` 等壳特征 → **无壳**，直接上 jadx。

用 androguard 解 Manifest：入口 `ui.StartActivity`，权限里有 `READ_SMS`、`ACCESS_WIFI_STATE` 等，无 `networkSecurityConfig`，**targetSdk=20**（很老，后面有用：默认信任用户 CA 证书，抓包无障碍）。

## 2. 静态分析：三步定位核心机密

jadx 反编译后 450 个自有类。定位思路是**搜关键词 → 顺调用链向上追**：

```
grep "Cipher.getInstance" → util/DesSecurity.java   (加密实现)
grep "DesSecurity("       → http/RequestUtil.java    (调用处)
追参数来源               → config/Config.java       (硬编码常量)
```

**成果一：加密算法**（DesSecurity.java）

```java
// key 先 MD5，取前 8 字节作 DES 密钥，CBC 模式，结果 Base64
SecretKey key = SecretKeyFactory.getInstance("DES")
        .generateSecret(new DESKeySpec(md5(keyBytes)));
Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
```

**成果二：硬编码常量**（Config.java）

```java
BASE_DES_KEY = "65102933";  BASE_DES_IV = "32028092";
DES_KEY = "!A^@#8$%";       DES_IV = "demin!@3";
BASE_APPEND = "sdlkjsdljf0j2fsjk";   // 签名盐
BASE_URL = "http://api.dodovip.com/api/";
```

**成果三：签名与封装流程**（RequestUtil / JsonRequest）

```
参数按 k=v 排序拼接 + "&key=盐" → MD5 大写 = sign
→ 整个 JSON 按 key 排序 → DES 加密 → Base64
→ 最终 POST 体: {"Encrypt":"<密文>"}
```

## 3. Frida 动态验证

静态结论要用运行时数据验证。hook 加解密函数 + Volley 网络层：

```javascript
Java.perform(function () {
    var D = Java.use("com.dodonew.online.util.DesSecurity");
    D.encrypt64.overload("[B").implementation = function (data) {
        console.log("[加密明文] " + Java.use("java.lang.String").$new(data, "UTF-8"));
        return this.encrypt64(data);
    };
    D.decrypt64.overload("java.lang.String").implementation = function (data) {
        var r = this.decrypt64(data);
        console.log("[解密明文] " + Java.use("java.lang.String").$new(r, "UTF-8"));
        return r;
    };
});
```

运行方式：

```bash
adb shell am force-stop com.dodonew.online
frida -U -f com.dodonew.online -l hook.js
```

手机上点一次登录，明文直接刷屏：

```json
{"equtype":"ANDROID","loginImei":"Androidnull",
 "sign":"D8B91921298D72462184B36DCEEC961B",
 "timeStamp":"1783440048431","userPwd":"***","username":"***"}
```

注意 `loginImei=Androidnull`——新 Android 拿不到 IMEI，服务端居然也放行。

## 4. 算法离线复现

```python
import hashlib, base64, json
from Crypto.Cipher import DES

def derive(key_str):
    return hashlib.md5(key_str.encode()).digest()[:8]

def encrypt64(plain, key="65102933", iv="32028092"):
    c = DES.new(derive(key), DES.MODE_CBC, iv.encode())
    b = plain.encode()
    b += bytes([8 - len(b) % 8]) * (8 - len(b) % 8)   # PKCS5
    return base64.b64encode(c.encrypt(b)).decode()

def make_sign(params, salt="sdlkjsdljf0j2fsjk"):
    items = sorted(f"{k}={v}" for k, v in params.items() if k != "sign")
    return hashlib.md5(("&".join(items) + "&key=" + salt).encode()).hexdigest().upper()
```

**验证标准**：重算 sign 与 App 生成的逐字节一致；App 发出的密文用脚本解出完整明文。两者都对上，静态分析闭环。

## 5. 独立客户端：脱离 App 通信

```python
def call(path, params):
    p = dict(params)
    p["timeStamp"] = str(int(time.time() * 1000))
    p["sign"] = make_sign(p)
    plain = json.dumps({k: p[k] for k in sorted(p)}, separators=(",", ":"))
    r = requests.post(BASE + path, json={"Encrypt": encrypt64(plain)},
                      headers={"User-Agent": "Dalvik/2.1.0 (Linux; U; Android 12)"})
    return json.loads(decrypt64(r.text.strip()))
```

全链路实测：

| 接口 | 结果 |
|---|---|
| `user/qqLogin` | `code:1` + userId |
| `oth/city` | 175 城市及 domainid |
| `oth/netbarList` | 按域返回网点列表（netBarId）|
| `oth/online/state` | `domainId+netBarId+memberId(userId)` → `code:1` |

响应同样是 DES 密文，解开后 `{"code":1,"data":{...}}`；`code:-10` 表示异地登录被踢。

## 6. 踩坑记录

1. **本地代理劫持**：requests 走了 127.0.0.1:7890 导致超时 → `proxies={"http": None, "https": None}` 直连
2. **GBK 控制台**：中文响应打印报错 → `sys.stdout.reconfigure(encoding="utf-8")`
3. **memberId 试错**：服务器报错就是文档——`account` 报 `code:7`，`userId` 正确
4. **404 ≠ 接口不存在**：这个后端对无效登录直接返回 404 HTML 错误页
5. **响应体可能很短**：hook 里 `substring(0,2000)` 会对 32 字节响应越界

## 7. 总结

完整链路：

```
信息收集 → 加固检测 → 反编译 → 密钥提取 → 动态验证 → 算法复现 → 独立通信
```

这套 App 的安全设计问题也很典型：**硬编码对称密钥**（等于没有加密）、**签名盐藏在客户端**（只防君子）、**设备标识形同虚设**。对开发者来说也是反面教材。

工具与脚本均已脱敏存档。Have fun & stay legal.
