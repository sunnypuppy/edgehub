# EdgeHub

**EdgeHub** 是一个基于 VLESS/Trojan 协议的代理节点汇聚工具，旨在为用户提供更便捷的代理节点订阅链接。它支持从多个第三方来源聚合节点信息，并生成适配多客户端的订阅链接。

## 特性

- 支持 VLESS 和 Trojan 协议
- 汇聚来自多个第三方的代理节点
- 支持配置第三方订阅链接
- 提供自定义的过滤选项，包括 IPv6 和非标准端口过滤
- 生成适用于多种客户端的订阅链接
    - V2BOX
    - Hiddify

## 本地部署

1. 确保你已安装 [Node.js](https://nodejs.org/) 和 npm。
2. 克隆此仓库：
   ```bash
   git clone https://github.com/sunnypuppy/edgehub.git
   cd edgehub
   ```
3. 安装依赖
   ```bash
   npm install
   ```
4. 运行
   ```bash
   npx wrangler dev 
   ```

## Cloudflare Workers 部署

1. 拷贝 [`/src/index.js`](https://github.com/sunnypuppy/edgehub/blob/master/src/index.js) 中的代码替换 workers 编辑器中内容，保存并部署。
2. 配置环境变量

    | 环境变量           | 必须性 | 默认值               | 内容格式                                | 示例                                      |
    |--------------------|--------|----------------------|-----------------------------------------|-------------------------------------------|
    | `EDGETUNNEL_UUID`  | 是     | 无                   | 一个唯一的用户 UUID 字符串               | `9e57b9c1-79ce-4004-a8ea-5a8e804fda51`   |
    | `EDGETUNNEL_HOST`  | 是     | 无                   | 主机名或域名                            | `your.edgetunnel.host.com`               |
    | `EDGETUNNEL_PATH`  | 否     | `/?ed=2048`          | 代理路径                                | `/vless?ed=2048`                        |
    | `ADDR_SETS`        | 是     | 无                   | JSON 字符串，包含代理节点的配置信息       | 见下方示例                               |

    **ADDR_SETS 示例值:**

    ```json
    {
        "links": [
            "https://example.com/auto",
            "https://example.com/custom-path"
        ],
        "addresses": [
            "127.0.0.1:8443#localhost_v4",
            "127.0.0.1#localhost_v4_no_port",
            "[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:443#localhost_v6",
            "[2001:0db8:85a3:0000:0000:8a2e:0370:7334]#localhost_v6_no_port"
        ],
        "domains": [
            "example.com",
            "www.example.com",
            "example.com:8443"
        ]
    }
    ```

## 使用

部署完成后，访问 `https://your-domain` 地址可查看接口使用方式。

```
Usage: Please use the following format to access the subscription:

    http://localhost:8787/sub/{your-edgetunnel-uuid}

Supported URL parameters:

- host
    The domain of your edgetunnel.
- path (optional)
    Path to specify custom path for your edgetunnel (default is /?ed=2048 ).
- ipv6 (optional)
    Specify if IPv6 addresses should be return (1 for yes, 0 for no, default is 0).
- cfport (optional)
    Specify if only return cloudflare standard ports (1 for yes, 0 for no, default is 0).
- base64 (optional)
    Specify if the output should be base64 encoded (1 for yes, 0 for no, default is 1).

Example usage:

1. Basic subscription:
http://localhost:8787/sub/9e57b9c1-79ce-4004-a8ea-5a8e804fda51

2. With parameters:
http://localhost:8787/sub/9e57b9c1-79ce-4004-a8ea-5a8e804fda51?host=example.com&path=/custom/path?ed=2048&ipv6=0&cfport=1&base64=1
```
