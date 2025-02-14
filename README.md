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
    - Sing-box (增加 client=singbox 请求参数)

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

    | 环境变量           | 必须     | 默认值              | 内容格式                                | 示例                                      |
    |--------------------|--------|----------------------|-----------------------------------------|-------------------------------------------|
    | `EDGETUNNEL_UUID`  | 是     | 无              | 一个唯一的用户 UUID 字符串               | `9e57b9c1-79ce-4004-a8ea-5a8e804fda51`   |
    | `EDGETUNNEL_HOST`  | 是     | 无              | 主机名或域名                            | `your.edgetunnel.host.com`               |
    | `EDGETUNNEL_VLESS_PATH`  | 否     | `/?ed=2048`     | VLESS 协议代理路径                                | `/vless?ed=2048`                        |
    | `EDGETUNNEL_TROJAN_PATH`  | 否     | `/?ed=2048`     | Trojan 协议代理路径                                | `/trojan?ed=2048`                        |
    | `NODE_AGG_CONFIG`        | 否     | 无              | JSON 字符串，包含代理节点的配置信息       | 见下方示例                               |

    **NODE_AGG_CONFIG 示例值:**

    ```json
    {
        "CF优选订阅@xxx": {
            "parse_type": "sub_link",
            "url": "https://xxxxxx/sub?uuid=ffffffff-ffff-ffff-ffff-ffffffffffff&host=example.com",
            "replace_backend": true
        },
        "xxx机场订阅": {
            "parse_type": "sub_link",
            "url": "https://xxx.com/xxx",
            "headers": {
                "user-agent": "v2rayN/7.7.1"
            }
        },
        "CF优选IP": {
            "parse_type": "cf_prefer_ip",
            "outbounds_type": "urltest",
            "datas": [
                "[2606:4700::]:443#Phoenix_v6"
            ]
        },
        "CF优选域名": {
            "parse_type": "cf_prefer_domain",
            "outbounds_type": "urltest",
            "datas": [
                "icook.hk",
                "www.visa.com.sg",
                "www.web.com"
            ]
        },
        "Serv00": {
            "parse_type": "raw_uri",
            "datas": [
                "hysteria2://ffffffff-ffff-ffff-ffff-ffffffffffff@s16.serv00.com:12345?sni=bing.com#s16-hy2",
                "vless://ffffffff-ffff-ffff-ffff-ffffffffffff@s16.serv00.com:12345?host=s16.serv00.com&path=/vless&sni=s16.serv00.com#s16-vless"
            ]
        }
    }
    ```

## 使用

部署完成后，访问 `https://your-domain` 地址可查看接口使用方式。

## 许可证

此项目采用 [MIT](https://github.com/sunnypuppy/edgehub/blob/master/LICENSE) 许可证。
