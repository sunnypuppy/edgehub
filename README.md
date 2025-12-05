# EdgeHub

**EdgeHub** 是一个多协议代理节点汇聚工具，旨在为用户提供更便捷的代理节点订阅链接。它支持从多个第三方来源聚合节点信息，并生成适配多客户端的订阅链接。

## 特性

- 支持 VLESS/Trojan/VMess/Tuic/Hysteria2 等多协议
- 汇聚来自多个第三方的代理节点
- 支持配置第三方订阅链接
- 提供自定义的过滤选项，包括 IPv6 和非标准端口过滤
- 生成适用于多种客户端的订阅链接
  - V2BOX
  - Hiddify
  - Karing
  - NekoBox
  - Sing-box (增加 client=singbox 请求参数)

## 本地部署

1. 确保你已安装 [Node.js](https://nodejs.org/) 和 npm。
2. 克隆此仓库：
   ```bash
   git clone https://github.com/sunnypuppy/edgehub.git
   cd edgehub
   ```
3. 初始化 & 依赖安装
   ```bash
   npm init -y && npm install
   ```
4. 运行
   ```bash
   npx wrangler dev
   ```

## Cloudflare Workers 部署

1. 拷贝 [`/src/index.js`](https://github.com/sunnypuppy/edgehub/blob/master/src/index.js) 中的代码替换 workers 编辑器中内容，保存并部署。
2. 配置环境变量

   | 环境变量                 | 必须 | 默认值    | 内容格式                            | 示例                                   |
   | ------------------------ | ---- | --------- | ----------------------------------- | -------------------------------------- |
   | `EDGETUNNEL_UUID`        | 是   | 无        | 一个唯一的用户 UUID 字符串          | `9e57b9c1-79ce-4004-a8ea-5a8e804fda51` |
   | `EDGETUNNEL_HOST`        | 是   | 无        | 主机名或域名                        | `your.edgetunnel.host.com`             |
   | `EDGETUNNEL_VLESS_PATH`  | 否   | `/vless`  | VLESS 协议代理路径                  | `/vless`                               |
   | `EDGETUNNEL_TROJAN_PATH` | 否   | `/trojan` | Trojan 协议代理路径                 | `/trojan`                              |
   | `NODE_AGG_CONFIG`        | 否   | 无        | JSON 字符串，包含代理节点的配置信息 | 见下方示例                             |

   **NODE_AGG_CONFIG 示例值:**

   ```json
   {
   	"cf_prefer_ip demo": {
   		"parse_type": "cf_prefer_ip",
   		"outbounds_type": "urltest",
   		"datas": ["127.0.0.1", "127.0.0.2#custom-name", "127.0.0.3:12345#custom-port", "hysteria2://127.0.0.4:12345#custom-protocol"]
   	},
   	"cf_prefer_domain demo": {
   		"parse_type": "cf_prefer_domain",
   		"outbounds_type": "urltest",
   		"datas": ["example.com", "custom-port.example.com:12345"]
   	},
   	"sub_link demo": {
   		"parse_type": "sub_link",
   		"outbounds_type": "urltest",
   		"url": "https://your.sublink.com",
   		"replace_backend": true
   	},
   	"sub_link demo-2": {
   		"parse_type": "sub_link",
   		"outbounds_type": "selector",
   		"url": "https://your.sublink.com",
   		"headers": {
   			"user-agent": "v2rayN/7.7.1"
   		}
   	},
   	"raw_uri demo": {
   		"parse_type": "raw_uri",
   		"outbounds_type": "selector",
   		"datas": [
   			"hysteria2://127.0.0.1:8801#xxx-hy2",
   			"vless://127.0.0.1:8802#xxx-vless",
   			"tuic://[::1]:8803#xxx-tuic",
   			"vmess://[::1]:8804#xxx-vmess",
   			"trojan://[::1]:8805#xxx-trojan"
   		]
   	}
   }
   ```

## 使用

部署完成后，访问 `https://your-domain` 地址可查看接口使用方式。

## 许可证

此项目采用 [MIT](https://github.com/sunnypuppy/edgehub/blob/master/LICENSE) 许可证。
