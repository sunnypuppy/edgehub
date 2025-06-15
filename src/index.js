let edgetunnelUUID = '9e57b9c1-79ce-4004-a8ea-5a8e804fda51';
let edgetunnelHost = 'your.edgetunnel.host.com';
let edgetunnelVLESSPATH = '/vless?ed=2048';
let edgetunnelTrojanPATH = '/trojan?ed=2048';
let edgetunnelProtocol = 'vless';

const cfHTTPPorts = new Set(['80', '8080', '8880', '2052', '2082', '2086', '2095']);
const cfHTTPSPorts = new Set(['443', '2053', '2083', '2087', '2096', '8443']);

let nodeAggConfig;

export default {
	async fetch(request, env, ctx) {
		try {
			const url = new URL(request.url);

			edgetunnelUUID = env.EDGETUNNEL_UUID || edgetunnelUUID;
			edgetunnelHost = url.searchParams.get('host') || env.EDGETUNNEL_HOST || edgetunnelHost;
			edgetunnelVLESSPATH = url.searchParams.get('vless_path') || env.EDGETUNNEL_VLESS_PATH || edgetunnelVLESSPATH;
			edgetunnelTrojanPATH = url.searchParams.get('trojan_path') || env.EDGETUNNEL_TROJAN_PATH || edgetunnelTrojanPATH;
			edgetunnelProtocol = url.searchParams.get('protocol') || env.EDGETUNNEL_PROTOCOL || edgetunnelProtocol;

			nodeAggConfig = nodeAggConfig || (env.NODE_AGG_CONFIG && JSON.parse(env.NODE_AGG_CONFIG));

			const options = {
				addrtype: url.searchParams.get('addrtype'),
				cfport: url.searchParams.get('cfport'),
				base64: url.searchParams.get('base64'),
				clienttype: url.searchParams.get('client'),
			};

			switch (url.pathname) {
				case `/sub/${edgetunnelUUID}`: // uuid as the default sub passwd
					return new Response(await getSubConfig(options));
				default:
					return new Response(getUsage(request));
			}
		} catch (error) {
			console.error(error);
			return new Response(`Internal Server Error`);
		}
	},
};

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
					port: parseInt(url.port, 10),
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
	switch (options.clienttype) {
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
	filteredNodes.push({ protocol: edgetunnelProtocol, address: edgetunnelHost, port: '443', name: 'edgetunnel' });

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
						return `${node.protocol}://${userInfo}/?security=reality&sni=${sni}&pbk=${node.pbk}&sid=${node.sid}&fp=chrome&flow=xtls-rprx-vision#${node.name}`;
					}
					return `${node.protocol}://${userInfo}/?security=tls&sni=${sni}&fp=chrome&allowInsecure=1&type=${type}&path=${path}&host=${host}#${node.name}`;
				case 'trojan':
					return `${node.protocol}://${userInfo}/?security=tls&sni=${sni}&fp=chrome&allowInsecure=1&type=${type}&path=${path}&host=${host}#${node.name}`;
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
								fp: 'chrome',
							})
						)
					);
				case 'hysteria2':
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
							fingerprint: 'chrome',
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
		default:
			break;
	}
}

async function getSingBoxSubConfig(options, nodesByGroup) {
	// Base configuration template
	const singboxSubConfig = {
		log: {
			disabled: false,
			level: 'info',
			timestamp: true,
		},
		dns: {
			servers: [
				{ tag: 'google', address: 'tls://8.8.8.8' },
				{ tag: 'local', address: '223.5.5.5', detour: 'direct' },
			],
			rules: [
				{ outbound: 'any', server: 'local' },
				{ clash_mode: 'Direct', server: 'local' },
				{ clash_mode: 'Global', server: 'google' },
				{ rule_set: 'geosite-geolocation-cn', server: 'local' },
			],
		},
		ntp: {
			enabled: true,
			server: 'time.apple.com',
			server_port: 123,
			interval: '30m',
			detour: 'direct',
		},
		inbounds: [
			{
				type: 'tun',
				tag: 'tun-in',
				address: ['172.19.0.1/30', 'fdfe:dcba:9876::1/126'],
				auto_route: true,
				strict_route: false,
			},
		],
		outbounds: [
			{ type: 'direct', tag: 'direct' },
			node2SingBoxOutbound({ protocol: edgetunnelProtocol, address: edgetunnelHost, port: '443', name: 'edgetunnel' }),
		],
		route: {
			rules: [
				{ action: 'sniff' },
				{ type: 'logical', mode: 'or', rules: [{ protocol: 'dns' }, { port: 53 }], action: 'hijack-dns' },
				{ clash_mode: 'Direct', outbound: 'direct' },
				{ clash_mode: 'Global', outbound: '节点选择' },
				{ rule_set: ['geoip-cn', 'geosite-geolocation-cn'], outbound: 'direct' },
				{ domain_suffix: ['cloudflare.com', 'cloudflare.dev'], outbound: 'direct' },
			],
			rule_set: [
				{
					tag: 'geoip-cn',
					type: 'remote',
					format: 'binary',
					url: 'https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs',
					download_detour: '节点选择',
				},
				{
					tag: 'geosite-geolocation-cn',
					type: 'remote',
					format: 'binary',
					url: 'https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-geolocation-cn.srs',
					download_detour: '节点选择',
				},
			],
			final: '节点选择',
			auto_detect_interface: true,
		},
		experimental: {
			cache_file: {
				enabled: true,
			},
		},
	};

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

	selector_outbounds.push('edgetunnel');
	selector_outbounds.push('direct');

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
