let edgetunnelUUID = '9e57b9c1-79ce-4004-a8ea-5a8e804fda51';
let edgetunnelHost = 'your.edgetunnel.host.com';
let edgetunnelVLESSPATH = '/vless?ed=2048';
let edgetunnelTrojanPATH = '/trojan?ed=2048';
let edgetunnelProtocol = 'vless';

const cfHTTPPorts = new Set(['80', '8080', '8880', '2052', '2082', '2086', '2095']);
const cfHTTPSPorts = new Set(['443', '2053', '2083', '2087', '2096', '8443']);

let nodeAggConfig;
let clientType, clientVersion, clientUA;

export default {
	async fetch(request, env, ctx) {
		try {
			const url = new URL(request.url);

			edgetunnelUUID = env.EDGETUNNEL_UUID || edgetunnelUUID;
			edgetunnelHost = url.searchParams.get('host') || env.EDGETUNNEL_HOST || edgetunnelHost;
			edgetunnelVLESSPATH = url.searchParams.get('vless_path') || env.EDGETUNNEL_VLESS_PATH || edgetunnelVLESSPATH;
			edgetunnelTrojanPATH = url.searchParams.get('trojan_path') || env.EDGETUNNEL_TROJAN_PATH || edgetunnelTrojanPATH;
			edgetunnelProtocol = url.searchParams.get('protocol') || env.EDGETUNNEL_PROTOCOL || edgetunnelProtocol;

			await loadClientInfo(request);
			await loadNodeAggConfig(request, env);

			const options = {
				addrtype: url.searchParams.get('addrtype'),
				cfport: url.searchParams.get('cfport'),
				base64: url.searchParams.get('base64'),
			};

			switch (url.pathname) {
				case `/sub/${edgetunnelUUID}`: // uuid as the default sub passwd
					return new Response(await getSubConfig(options));
				case `/sub/${edgetunnelUUID}/config`:
					return handleConfigRoute(request, env);
				default:
					return new Response(getUsage(request));
			}
		} catch (error) {
			console.error(error);
			return new Response(`Internal Server Error`);
		}
	},
};

async function loadClientInfo(request) {
	const url = new URL(request.url);

	clientType = url.searchParams.get('client');
	clientVersion = url.searchParams.get('client_version');
	if (clientType && clientVersion) return;

	clientUA = request.headers.get('user-agent');

	// singbox
	let match = clientUA.match(/sing-box (\d+\.\d+\.\d+)/i); // SFM/1.11.4 (Build 394; sing-box 1.11.4; language en_CN)
	if (match) {
		clientType = 'singbox';
		clientVersion = match[1];
		return;
	}

	// v2rayN
	match = clientUA.match(/^v2rayN\/(\d+\.\d+\.\d+)/i); // v2rayN/7.16.5
	if (match) {
		clientType = 'v2rayn';
		clientVersion = match[1];
		return;
	}
}

async function loadNodeAggConfig(request, env) {
	const param = new URL(request.url).searchParams.get("nodeaggconfig");
	if (param) {
		const parsedParam = JSON.parse(param);
		if (parsedParam && Object.keys(parsedParam).length > 0) {
			nodeAggConfig = parsedParam;
			return;
		}
	}

	if (env.KV_EDGEHUB) {
		const raw = await env.KV_EDGEHUB.get("NODE_AGG_CONFIG");
		if (raw) {
			const parsed = JSON.parse(raw);
			if (parsed && Object.keys(parsed).length > 0) {
				nodeAggConfig = parsed;
				return;
			}
		}
	}
	if (env.NODE_AGG_CONFIG) {
		const parsedEnv = JSON.parse(env.NODE_AGG_CONFIG);
		if (parsedEnv && Object.keys(parsedEnv).length > 0) {
			nodeAggConfig = parsedEnv;
			return;
		}
	}
	if (nodeAggConfig && Object.keys(nodeAggConfig).length > 0) return;
	nodeAggConfig = {};
}

function getAddressType(address) {
	const ipv4Regex = /^((\d|[1-9]\d|1\d{2}|2[0-4]\d|25[0-5])\.){3}(\d|[1-9]\d|1\d{2}|2[0-4]\d|25[0-5])$/;

	if (ipv4Regex.test(address)) {
		return 'ipv4';
	}

	if (address.includes(':')) {
		return 'ipv6';
	}

	return 'domain';
}

function base64EncodeUtf8(str) {
	const bytes = new TextEncoder().encode(str);
	return btoa(String.fromCharCode(...bytes));
}

function base64DecodeUtf8(base64Str) {
	const binaryStr = atob(base64Str);
	const bytes = Uint8Array.from(binaryStr, (c) => c.charCodeAt(0));
	return new TextDecoder().decode(bytes);
}

async function parseNodesFromSubLink(links, concurrencyLimit = 5) {
	const allNodes = [];

	async function fetchAndParse(link) {
		try {
			const response = await fetch(link.url, { headers: link.headers });
			const responseText = await response.text();
			if (responseText.match(/^[A-Za-z0-9+/]+={0,2}$/)) {
				const lines = base64DecodeUtf8(responseText).trim().split('\n');
				allNodes.push(...parseNodesFromURIs(lines, link.replace_backend));
				return;
			}
		} catch (error) {
			console.error(error);
		}
	}

	// Limit concurrent fetches
	const pool = [];
	for (let i = 0; i < links.length; i += concurrencyLimit) {
		const batch = links.slice(i, i + concurrencyLimit).map((link) => fetchAndParse(link));
		pool.push(Promise.all(batch)); // Process batch in parallel
	}
	await Promise.all(pool);

	const uniqueNodes = new Map();
	allNodes.forEach((node) => uniqueNodes.set(`${node.protocol}:${node.address}:${node.port}:${node.host}`, node));
	return Array.from(uniqueNodes.values());
}

function parseNodesFromAddress(addresses) {
	const allNodes = [];

	const regex = /^((?<protocol>\w+):\/\/)?(?<ip>(\d{1,3}\.){3}\d{1,3}|\[[0-9a-fA-F:]+\])(:(?<port>\d+))?(#(?<name>.*))?$/;
	addresses.forEach((address) => {
		const match = address.match(regex);
		if (match) {
			const { protocol, ip, port, name } = match.groups;
			const node = {
				protocol: protocol || edgetunnelProtocol,
				address: ip,
				port: port || '443',
				name: name || ip,
			};
			allNodes.push(node);
		}
	});

	return allNodes;
}

function parseNodesFromDomain(domains) {
	const allNodes = [];

	domains.forEach((domain) => {
		const [domainPart, portPart] = domain.split(':');

		const node = {
			protocol: edgetunnelProtocol,
			address: domainPart,
			port: portPart || '443',
			name: domainPart,
		};

		allNodes.push(node);
	});

	return allNodes;
}

function parseNodesFromURIs(uris, replace_backend = false) {
	return uris
		.map((uri) => {
			if (!uri.trim()) return null;
			try {
				const url = new URL(decodeURIComponent(uri));
				return {
					protocol: url.protocol.slice(0, -1),
					address: url.hostname,
					port: parseInt(url.port, 10) || 443,
					name: url.hash.slice(1),

					uuid: replace_backend ? null : url.username,
					password: replace_backend ? null : url.password,
					host: replace_backend ? null : url.searchParams.get('host') || url.searchParams.get('sni'),
					path: replace_backend ? null : url.searchParams.get('path'),
					type: replace_backend ? null : url.searchParams.get('type'),
					sni: replace_backend ? null : url.searchParams.get('sni') || url.searchParams.get('host'),
					security: replace_backend ? null : url.searchParams.get('security'),
					pbk: replace_backend ? null : url.searchParams.get('pbk'),
					sid: replace_backend ? null : url.searchParams.get('sid'),
				};
			} catch (error) {
				console.error(error);
				return null;
			}
		})
		.filter((node) => node !== null);
}

async function parseNodesFromGroups(groups) {
	let result = {};
	for (let groupName in groups) {
		const group = groups[groupName];
		const nodes = [];

		let node = [];
		switch (group.parse_type) {
			case 'cf_prefer_ip':
				node = parseNodesFromAddress(group.datas);
				node && nodes.push(...node);
				break;
			case 'cf_prefer_domain':
				node = parseNodesFromDomain(group.datas);
				node && nodes.push(...node);
				break;
			case 'sub_link':
				node = await parseNodesFromSubLink([group]);
				node && nodes.push(...node);
				break;
			default:
				node = parseNodesFromURIs(group.datas);
				node && nodes.push(...node);
				break;
		}

		if (nodes.length > 0) {
			result[groupName] = nodes;
		}
	}
	return result;
}

async function batchQueryIPGeolocation(ipList) {
	const url = 'http://ip-api.com/batch';
	const MAX_BATCH_SIZE = 100; // Maximum IPs per request

	async function fetchBatch(batch) {
		const response = await fetch(url, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify(batch),
		});

		if (!response.ok) throw new Error('Failed to fetch IP data');

		return await response.json();
	}

	// Split the IP list into chunks of 100
	const batches = [];
	for (let i = 0; i < ipList.length; i += MAX_BATCH_SIZE) {
		batches.push(ipList.slice(i, i + MAX_BATCH_SIZE));
	}

	// Fetch all batches and combine results
	const results = [];
	for (const batch of batches) {
		const batchResult = await fetchBatch(batch);
		results.push(...batchResult);
	}

	return results;
}

async function getSubConfig(options) {
	const nodesByGroup = await parseNodesFromGroups(nodeAggConfig);
	switch (clientType) {
		case 'singbox':
			return getSingBoxSubConfig(options, nodesByGroup);

		default:
			return getDefaultSubConfig(options, nodesByGroup);
	}
}

async function getDefaultSubConfig(options, nodesByGroup) {
	const uniqueNodes = new Map();
	Object.values(nodesByGroup).forEach((nodes) => {
		nodes.forEach((node) => uniqueNodes.set(`${node.protocol}:${node.address}:${node.port}:${node.host}`, node));
	});

	const filteredNodes = Array.from(uniqueNodes.values()).filter((node) => {
		if (cfHTTPPorts.has(node.port)) return false;
		if (options.cfport === '1' && !cfHTTPSPorts.has(node.port)) return false;
		if (options.addrtype && !options.addrtype.split(',').includes(getAddressType(node.address))) return false;
		return true;
	});
	// add default edge node
	// filteredNodes.push({ protocol: edgetunnelProtocol, address: edgetunnelHost, port: '443', name: 'edgetunnel' });

	const configs = await Promise.all(
		filteredNodes.map((node) => {
			const uuid = node.uuid || edgetunnelUUID;
			const password = node.password || '';
			const sni = node.sni || edgetunnelHost;
			const path = encodeURIComponent(
				node.path || (node.protocol === 'vless' ? edgetunnelVLESSPATH : node.protocol === 'trojan' ? edgetunnelTrojanPATH : '/')
			);
			const type = node.type || 'ws';
			const host = node.host || edgetunnelHost;

			const userInfo = `${uuid}${atob('QA==')}${node.address}:${node.port}`;
			switch (node.protocol) {
				case 'vless':
					if (node.security === 'reality') {
						return `${node.protocol}://${userInfo}/?security=reality&sni=${sni}&pbk=${node.pbk}&sid=${node.sid}&fp=randomized&flow=xtls-rprx-vision#${node.name}`;
					}
					return `${node.protocol}://${userInfo}/?security=tls&sni=${sni}&fp=randomized&allowInsecure=1&type=${type}&path=${path}&host=${host}#${node.name}`;
				case 'trojan':
					return `${node.protocol}://${userInfo}/?security=tls&sni=${sni}&fp=randomized&allowInsecure=1&type=${type}&path=${path}&host=${host}#${node.name}`;
				case 'vmess':
					return (
						`${node.protocol}://` +
						base64EncodeUtf8(
							JSON.stringify({
								v: '2',
								ps: `${node.name}`,
								add: `${node.address}`,
								port: `${node.port}`,
								id: `${uuid}`,
								net: `${type}`,
								host: `${host}`,
								path: `${decodeURIComponent(path)}`,
								scy: 'auto',
								tls: 'tls',
								sni: `${sni}`,
								fp: 'randomized',
							})
						)
					);
				case 'hysteria2':
					return `${node.protocol}://${userInfo}/?sni=${sni}&insecure=1#${node.name}`;
				case 'anytls':
					return `${node.protocol}://${userInfo}/?sni=${sni}&insecure=1#${node.name}`;
				case 'tuic':
					const tuicUserInfo = `${uuid}:${password}${atob('QA==')}${node.address}:${node.port}`;
					return `${node.protocol}://${tuicUserInfo}/?sni=${sni}&alpn=h3&congestion_control=bbr&insecure=1#${node.name}`;
				default:
					return '';
			}
		})
	);
	return options.base64 === '0' ? configs.join('\n') : Buffer.from(configs.join('\n'), 'utf-8').toString('base64');
}

function compareVersion(a, b, length = 3) {
	const normalize = (v, len) => {
		if (!v) return Array(len).fill(0);
		return v.replace(/^[vV]/, '')
			.split('.')
			.map(n => parseInt(n, 10) || 0)
			.concat(Array(len).fill(0))
			.slice(0, len);
	};

	const pa = normalize(a, length);
	const pb = normalize(b, length);

	for (let i = 0; i < length; i++) {
		if (pa[i] > pb[i]) return 1;  // a > b
		if (pa[i] < pb[i]) return -1; // a < b
	}
	return 0; // a == b
}

function node2SingBoxOutbound(node) {
	const uuid = decodeURIComponent(node.uuid || edgetunnelUUID);
	const password = node.password || '';
	const sni = node.sni || edgetunnelHost;
	const path =
		node.path || (node.protocol === 'vless' ? edgetunnelVLESSPATH : node.protocol === 'trojan' ? edgetunnelTrojanPATH : '/').split('?')[0];
	const host = node.host || edgetunnelHost;
	if (node.type && node.type !== 'ws') return;
	const type = 'ws';
	const tag = decodeURIComponent(node.name);

	switch (node.protocol) {
		case 'vless':
			if (node.security === 'reality') {
				return {
					type: node.protocol,
					tag: tag,
					server: node.address,
					server_port: parseInt(node.port, 10),
					uuid: uuid,
					flow: 'xtls-rprx-vision',
					tls: {
						enabled: true,
						server_name: sni,
						reality: {
							enabled: true,
							public_key: node.pbk,
							short_id: node.sid,
						},
						utls: {
							enabled: true,
							fingerprint: 'randomized',
						},
					},
				};
			}
			return {
				type: node.protocol,
				tag: tag,
				server: node.address,
				server_port: parseInt(node.port, 10),
				uuid: uuid,
				tls: {
					enabled: true,
					server_name: sni,
					insecure: true,
				},
				transport: {
					type: type,
					path: path,
					max_early_data: 2048,
					early_data_header_name: 'Sec-WebSocket-Protocol',
					headers: { host: host },
				},
			};
		case 'vmess':
			return {
				type: node.protocol,
				tag: tag,
				server: node.address,
				server_port: parseInt(node.port, 10),
				uuid: uuid,
				tls: {
					enabled: true,
					server_name: sni,
					insecure: true,
				},
				transport: {
					type: type,
					path: path,
					max_early_data: 2048,
					early_data_header_name: 'Sec-WebSocket-Protocol',
					headers: { host: host },
				},
			};
		case 'trojan':
			return {
				type: node.protocol,
				tag: tag,
				server: node.address,
				server_port: parseInt(node.port, 10),
				password: uuid,
				tls: {
					enabled: true,
					server_name: sni,
					insecure: true,
				},
				transport: {
					type: type,
					path: path,
					max_early_data: 2048,
					early_data_header_name: 'Sec-WebSocket-Protocol',
					headers: { host: host },
				},
			};
		case 'hysteria2':
			return {
				type: node.protocol,
				tag: tag,
				server: node.address,
				server_port: parseInt(node.port, 10),
				up_mbps: 100,
				down_mbps: 100,
				password: uuid,
				tls: {
					enabled: true,
					server_name: sni,
					insecure: true,
				},
			};
		case 'tuic':
			return {
				type: node.protocol,
				tag: tag,
				server: node.address,
				server_port: parseInt(node.port, 10),
				uuid: uuid,
				password: password,
				congestion_control: 'bbr',
				tls: {
					enabled: true,
					server_name: sni,
					alpn: ['h3'],
					insecure: true,
				},
			};
		case 'anytls':
			if (compareVersion(clientVersion, "1.12.0") < 0) break;
			return {
				type: node.protocol,
				tag: tag,
				server: node.address,
				server_port: parseInt(node.port, 10),
				password: uuid,
				tls: {
					enabled: true,
					server_name: sni,
					insecure: true,
				},
			};
		default:
			break;
	}
}

async function getSingBoxSubConfig(options, nodesByGroup) {
	// Base configuration template
	const singboxSubConfig = {
		log: { disabled: false, level: 'info', timestamp: true },
		dns: {
			servers: [],
			rules: [
				{ clash_mode: 'Global', server: 'remote_dns' },
				{ clash_mode: 'Direct', server: 'direct_dns' },
				{ domain_suffix: ["cdn.jsdelivr.net", "alidns.com", "doh.pub", "dot.pub", "360.cn", "onedns.net"], server: "direct_dns" },
				{ rule_set: 'geosite-geolocation-cn', server: 'direct_dns' },
				{ type: "logical", mode: "and", rules: [{ rule_set: "geosite-geolocation-!cn", invert: true }, { rule_set: "geoip-cn" }], server: "remote_dns", client_subnet: "114.114.114.114/24" },
			],
			independent_cache: true,
		},
		ntp: { enabled: true, server: 'time.apple.com', server_port: 123, interval: '30m', detour: 'direct' },
		inbounds: [{ type: 'tun', tag: 'tun-in', address: ['172.19.0.1/30'], auto_route: true, strict_route: true }],
		// inbounds: [{ type: 'mixed', tag: 'mixed-in', listen: "127.0.0.1", listen_port: 60808, set_system_proxy: true }],
		outbounds: [{ type: 'direct', tag: 'direct' }],
		route: {
			rules: [
				{ action: 'sniff' },
				{ type: 'logical', mode: 'or', rules: [{ protocol: 'dns' }, { port: 53 }], action: 'hijack-dns' },
				{ ip_is_private: true, outbound: 'direct' },
				{ clash_mode: 'Direct', outbound: 'direct' },
				{ clash_mode: 'Global', outbound: '节点选择' },
				{ type: 'logical', mode: 'or', rules: [{ port: 853 }, { network: "udp", port: 443 }, { protocol: "stun" }], action: "reject" },
				{ rule_set: 'geosite-geolocation-cn', outbound: 'direct' },
				{ type: 'logical', mode: 'and', rules: [{ rule_set: "geoip-cn" }, { rule_set: "geosite-geolocation-!cn", invert: true }], outbound: "direct" },
				{ domain_suffix: ['cloudflare.com', 'cloudflare.dev'], outbound: 'direct' },
			],
			rule_set: [
				{
					tag: 'geoip-cn', type: 'remote', format: 'binary', download_detour: 'direct',
					url: 'https://cdn.jsdelivr.net/gh/SagerNet/sing-geoip@rule-set/geoip-cn.srs',
				},
				{
					tag: 'geosite-geolocation-cn', type: 'remote', format: 'binary', download_detour: 'direct',
					url: 'https://cdn.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/geosite-geolocation-cn.srs',
				},
				{
					tag: 'geosite-geolocation-!cn', type: 'remote', format: 'binary', download_detour: 'direct',
					url: 'https://cdn.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/geosite-geolocation-!cn.srs',
				},
			],
			final: '节点选择',
			auto_detect_interface: true,
		},
		experimental: { cache_file: { enabled: true, store_rdrc: true } },
	};

	if (compareVersion(clientVersion, '1.12.0') < 0) {
		// singbox version < 1.12.0
		singboxSubConfig.dns.servers = [
			{ tag: 'remote_dns', address: 'tls://8.8.8.8' },
			{ tag: 'direct_dns', address: '223.5.5.5', detour: 'direct' },
		]
		// singboxSubConfig.dns.rules.unshift({ outbound: "any", server: "direct_dns" })
		singboxSubConfig.dns.rules.push({ outbound: "any", server: "direct_dns" })
	} else {
		// singbox version >= 1.12.0
		singboxSubConfig.dns.servers = [
			{ tag: "remote_dns", server: "cloudflare-dns.com", path: "/dns-query", domain_resolver: "hosts_dns", type: "https", detour: '节点选择' },
			{ tag: "direct_dns", server: "dns.alidns.com", path: "/dns-query", domain_resolver: "hosts_dns", type: "https" },
			{
				tag: "hosts_dns", type: "hosts", predefined: {
					"dns.google": ["8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"],
					"dns.alidns.com": ["223.5.5.5", "223.6.6.6", "2400:3200::1", "2400:3200:baba::1"],
					"one.one.one.one": ["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"],
					"1dot1dot1dot1.cloudflare-dns.com": ["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"],
					"cloudflare-dns.com": ["104.16.249.249", "104.16.248.249", "2606:4700::6810:f8f9", "2606:4700::6810:f9f9"],
					"dns.cloudflare.com": ["104.16.132.229", "104.16.133.229", "2606:4700::6810:84e5", "2606:4700::6810:85e5"],
					"dot.pub": ["1.12.12.12", "120.53.53.53"],
					"doh.pub": ["1.12.12.12", "120.53.53.53"],
					"dns.quad9.net": ["9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"],
					"dns.yandex.net": ["77.88.8.8", "77.88.8.1", "2a02:6b8::feed:0ff", "2a02:6b8:0:1::feed:0ff"],
					"dns.sb": ["185.222.222.222", "2a09::"],
					"dns.umbrella.com": ["208.67.220.220", "208.67.222.222", "2620:119:35::35", "2620:119:53::53"],
					"dns.sse.cisco.com": ["208.67.220.220", "208.67.222.222", "2620:119:35::35", "2620:119:53::53"],
					"engage.cloudflareclient.com": ["162.159.192.1", "2606:4700:d0::a29f:c001"]
				},
			},
		]
		singboxSubConfig.dns.rules.unshift({ action: "predefined", rcode: "NOTIMP", query_type: [64, 65] })
		singboxSubConfig.dns.rules.push({ ip_accept_any: true, server: "hosts_dns" })
		singboxSubConfig.route['default_domain_resolver'] = 'direct_dns';
	}

	const groups_outbounds = {};
	Object.entries(nodesByGroup).forEach(([groupName, nodes]) => {
		const group_outbounds = nodes.map(node2SingBoxOutbound).filter(Boolean);
		groups_outbounds[groupName] = group_outbounds;
		singboxSubConfig.outbounds.push(...group_outbounds);
	});

	const selector_outbounds = [];
	singboxSubConfig.outbounds.push({
		type: 'selector',
		tag: '节点选择',
		outbounds: selector_outbounds,
	});

	for (let groupName in groups_outbounds) {
		const group_outbounds = groups_outbounds[groupName];
		if (group_outbounds.length > 0) {
			singboxSubConfig.outbounds.push({
				type: nodeAggConfig[groupName].outbounds_type || 'selector',
				tag: groupName,
				outbounds: group_outbounds.map((outbound) => outbound.tag),
			});
			selector_outbounds.push(groupName);
		}
	}

	// Return JSON string of configuration
	return JSON.stringify(singboxSubConfig, null, 4);
}

function getUsage(request) {
	const url = new URL(request.url);
	const currentHost = url.host;

	return `
Usage: Please use the following format to access the subscription:

    ${url.protocol}//${currentHost}/sub/{your-edgetunnel-uuid}

Supported URL parameters:

- host
    The domain of your edgetunnel.
- vless_path (optional)
    Path to specify custom path for your edgetunnel vless protocol (default is /?ed=2048 ).
- trojan_path (optional)
    Path to specify custom path for your edgetunnel trojan protocol (default is /?ed=2048 ).
- protocol (optional)
    Specify used default protocol types for no protocol parsed node (vless or trojan, default is vless).
- addrtype (optional)
    Specify which address types to return (default is return all types):
    - (empty)      : return all address types (ipv4, ipv6, and domain).
    - Combinations : You can combine values, e.g., 'ipv4,ipv6' to return both IPv4 and IPv6 addresses.
- cfport (optional)
    Specify if only return cloudflare standard ports (1 for yes, 0 for no, default is 0).
- base64 (optional)
    Specify if the output should be base64 encoded (1 for yes, 0 for no, default is 1).
- client (optional)
    Specifies an additional client subscription format that is supported (e.g. 'singbox' for sing-box client, default is v2ray).

Example usage:

1. Basic subscription:
   ${url.protocol}//${currentHost}/sub/9e57b9c1-79ce-4004-a8ea-5a8e804fda51

2. With parameters:
   ${url.protocol}//${currentHost}/sub/9e57b9c1-79ce-4004-a8ea-5a8e804fda51?host=example.com&path=/custom/path?ed=2048&addrtype=ip&cfport=1&base64=1

3. Support sing-box client:
   ${url.protocol}//${currentHost}/sub/9e57b9c1-79ce-4004-a8ea-5a8e804fda51?client=singbox

------------------------------------------------------
Please use the following format to access the configuration manager:

    ${url.protocol}//${currentHost}/sub/{your-edgetunnel-uuid}/config

    `.trim();
}

async function handleConfigRoute(request, env) {
	const method = request.method.toUpperCase();

	if (method === 'POST') {
		if (!env.KV_EDGEHUB) {
			return new Response('KV binding missing. Please bind KV to enable editing.', { status: 400 });
		}
		const data = await request.json();
		await env.KV_EDGEHUB.put("NODE_AGG_CONFIG", JSON.stringify(data));
		nodeAggConfig = data;
		return new Response('OK', { status: 200 });
	}

	if (method === 'GET') {
		const initial = JSON.stringify(nodeAggConfig || {}, null, 2);
		const hasKV = !!env.KV_EDGEHUB;

		const html = `
<!DOCTYPE html>
<html lang="zh">

<head>
    <meta charset="UTF-8" />
    <title>聚合节点配置编辑器</title>
    <style>
        html,
        body {
            margin: 0;
            padding: 0;
            height: 100%;
            overflow: hidden;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background-color: #1e1e1e;
            color: #fff;
        }

        #editor,
        #diffEditor {
            height: 90vh;
            width: 100vw;
            display: none;
            border-top: 1px solid #333;
        }

        #actions {
            padding: 15px 20px;
            text-align: center;
            background-color: #252526;
            border-bottom: 1px solid #444;
            display: flex;
            flex-wrap: wrap;
            justify-content: center;
            gap: 10px;
        }

        button {
            padding: 8px 16px;
            font-size: 14px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            color: #fff;
            transition: background-color 0.2s ease;
        }

        #editBtn {
            background-color: #2d8cf0;
        }

        #editBtn:hover {
            background-color: #1e6bb8;
        }

        #submitBtn {
            background-color: #19be6b;
        }

        #submitBtn:hover {
            background-color: #0f9d58;
        }

        #resetBtn {
            background-color: #f56c6c;
        }

        #resetBtn:hover {
            background-color: #dd6161;
        }

        #formatBtn {
            background-color: #34c38f;
        }

        #formatBtn:hover {
            background-color: #2ea97a;
        }

        #toggleDiffBtn {
            background-color: #ab47bc;
        }

        #toggleDiffBtn:hover {
            background-color: #9c27b0;
        }

        button:disabled {
            background-color: #555;
            cursor: not-allowed;
            opacity: 0.7;
        }

        #msg {
            display: inline-block;
            margin-left: 10px;
            min-width: 160px;
            font-size: 14px;
            line-height: 32px;
            color: #f0f0f0;
        }
    </style>
    <script src="https://cdn.jsdelivr.net/npm/monaco-editor@0.45.0/min/vs/loader.js"></script>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/toastify-js/src/toastify.min.css" />
    <script src="https://cdn.jsdelivr.net/npm/toastify-js"></script>
</head>

<body>
    <div id="actions">
        <button id="editBtn" onclick="toggleEdit()">编辑</button>
        <button id="formatBtn" onclick="formatCode()">格式化</button>
        <button id="resetBtn" onclick="reset()">重置</button>
        <button id="toggleDiffBtn" onclick="toggleDiff()">对比</button>
        <button id="submitBtn" onclick="submit()" ${hasKV ? '' : 'disabled title="未绑定 KV，无法提交配置"'}>提交</button>
    </div>
    <div id="editor"></div>
    <div id="diffEditor"></div>

    <script>
        let editor, diffEditor;
        let isEditing = false;
        let tempData = ${initial};
        const original = ${initial};
        let originalModel, modifiedModel;

        require.config({ paths: { 'vs': 'https://cdn.jsdelivr.net/npm/monaco-editor@0.45.0/min/vs' } });
        require(['vs/editor/editor.main'], function () {
            editor = monaco.editor.create(document.getElementById('editor'), {
                value: JSON.stringify(original, null, 2),
                language: 'json',
                theme: 'vs-dark',
                readOnly: true,
                automaticLayout: true
            });
            document.getElementById('editor').style.display = 'block';

            diffEditor = monaco.editor.createDiffEditor(document.getElementById('diffEditor'), {
                theme: 'vs-dark',
                readOnly: true,
                automaticLayout: true
            });
        });

        function toggleEdit() {
            isEditing = !isEditing;
            editor.updateOptions({ readOnly: !isEditing });
            const btn = document.getElementById('editBtn');
            btn.textContent = isEditing ? '保存' : '编辑';

            if (!isEditing) {
                try {
                    tempData = JSON.parse(editor.getValue());
                    showMsg("已保存到临时变量", "green");
                } catch (e) {
                    showMsg("保存失败: JSON 无效", "red");
                    isEditing = true;
                    editor.updateOptions({ readOnly: false });
                    btn.textContent = '保存';
                }
            }

            updateButtonVisibility();
        }

        function formatCode() {
            const value = editor.getValue();
            try {
                const parsed = JSON.parse(value);
                editor.setValue(JSON.stringify(parsed, null, 2));
                showMsg("格式化成功", "green");
            } catch (err) {
                showMsg("格式化失败: " + err.message, "red");
            }
        }

        function reset() {
            editor.setValue(JSON.stringify(original, null, 2));
            showMsg("已重置为初始值", "gray");
        }

        function toggleDiff() {
            const editorDiv = document.getElementById('editor');
            const diffDiv = document.getElementById('diffEditor');
            const btn = document.getElementById('toggleDiffBtn');

            if (diffDiv.style.display === 'block') {
                exitDiff();
                btn.textContent = '对比';
            } else {
                showDiff();
                btn.textContent = '返回编辑';
            }

            updateButtonVisibility();
        }

        function exitDiff() {
            document.getElementById('editor').style.display = 'block';
            document.getElementById('diffEditor').style.display = 'none';
        }

        function showDiff() {
            document.getElementById('editor').style.display = 'none';
            document.getElementById('diffEditor').style.display = 'block';

            if (originalModel) originalModel.dispose();
            if (modifiedModel) modifiedModel.dispose();
            originalModel = monaco.editor.createModel(JSON.stringify(original, null, 2), 'json');
            modifiedModel = monaco.editor.createModel(JSON.stringify(tempData, null, 2), 'json');
            diffEditor.setModel({ original: originalModel, modified: modifiedModel });
        }

        async function submit() {
            try {
                if (JSON.stringify(tempData) === JSON.stringify(original)) {
                    showMsg("配置信息一致，无需提交", "gray");
                    return;
                }

                const res = await fetch(location.pathname, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(tempData)
                });
                if (res.ok) {
                    showMsg("提交成功", "green");
                } else {
                    const err = await res.text();
                    showMsg("提交失败: " + err, "red");
                }
            } catch (e) {
                showMsg("提交异常: " + e.message, "red");
            }
        }

        function showMsg(text, color) {
            Toastify({
                text: text,
                duration: 3000, // auto close after 3s
                close: true, // show close button
                gravity: "top", // 'top' or 'bottom'
                position: color === 'red' ? 'center' : 'right', // center for error, right for info
                backgroundColor: color === 'red' ? "#e74c3c" : (color === 'green' ? "#27ae60" : "#34495e"),
                stopOnFocus: true, // pause on hover
            }).showToast();
        }

        function updateButtonVisibility() {
            const formatBtn = document.getElementById('formatBtn');
            const resetBtn = document.getElementById('resetBtn');
            const submitBtn = document.getElementById('submitBtn');
            const editBtn = document.getElementById('editBtn');
            const toggleDiffBtn = document.getElementById('toggleDiffBtn');

            const inDiff = diffEditor && diffEditor.getContainerDomNode().style.display === 'block';

            editBtn.textContent = isEditing ? '保存' : '编辑';
            editBtn.style.display = inDiff ? 'none' : 'block';

            formatBtn.style.display = (isEditing && !inDiff) ? 'block' : 'none';
            resetBtn.style.display = (isEditing && !inDiff) ? 'block' : 'none';

            submitBtn.style.display = (inDiff || isEditing) ? 'none' : 'block';

            toggleDiffBtn.textContent = inDiff ? '返回编辑' : '对比';
            toggleDiffBtn.style.display = isEditing ? 'none' : 'block';
        }

        window.addEventListener('DOMContentLoaded', updateButtonVisibility);
        window.addEventListener('keydown', function (e) {
            if ((e.ctrlKey || e.metaKey) && e.key === 's') {
                e.preventDefault();
                if (isEditing) toggleEdit();
            }

            if (e.key === 'Escape' && diffEditor && diffEditor.getContainerDomNode().style.display === 'block') {
                toggleDiff();
            }
        });
    </script>
</body>

</html>
`;

		return new Response(html, {
			headers: { 'Content-Type': 'text/html; charset=UTF-8' }
		});
	}

	return new Response('Method Not Allowed', { status: 405 });
}
