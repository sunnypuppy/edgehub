let edgetunnelUUID = '9e57b9c1-79ce-4004-a8ea-5a8e804fda51';
let edgetunnelHost = 'your.edgetunnel.host.com';
let edgetunnelVLESSPATH = '/?ed=2048';
let edgetunnelTrojanPATH = '/?ed=2048';
let edgetunnelProtocol = 'vless';

let addrSets = `
{
    "links": [
        "https://example.com/auto",
        "https://example.com/custom-path"
    ],
    "addresses": [
        "trojan:127.0.0.1:8443#localhost_v4",
        "127.0.0.2#localhost_v4_no_port",
        "[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:443#localhost_v6",
        "trojan:[2001:0db8:85a3:0000:0000:8a2e:0371:7334]#localhost_v6_no_port"
    ],
    "domains": [
        "example.com",
        "www.example.com",
        "example.com:8443"
    ],
	"privates":[
		"vless://9e57b9c1-79ce-4004-a8ea-5a8e804fda51@127.0.0.1:443?host=your.edgetunnel.host.com&path=/vless?ed%3D2048&sni=your.edgetunnel.host.com#test-vless",
		"trojan://9e57b9c1-79ce-4004-a8ea-5a8e804fda51@127.0.0.1:443?host=your.edgetunnel.host.com&path=/trojan?ed%3D2048&sni=your.edgetunnel.host.com#test-trojan",
		"hysteria2://9e57b9c1-79ce-4004-a8ea-5a8e804fda51@127.0.0.1:443?sni=your.edgetunnel.host.com#test-hy2"
	]
}
`;

const cfHTTPPorts = new Set(['80', '8080', '8880', '2052', '2082', '2086', '2095']);
const cfHTTPSPorts = new Set(['443', '2053', '2083', '2087', '2096', '8443']);

export default {
	async fetch(request, env, ctx) {
		const url = new URL(request.url);

		edgetunnelUUID = env.EDGETUNNEL_UUID || edgetunnelUUID;
		edgetunnelHost = url.searchParams.get('host') || env.EDGETUNNEL_HOST || edgetunnelHost;
		edgetunnelVLESSPATH = url.searchParams.get('vless_path') || env.EDGETUNNEL_VLESS_PATH || edgetunnelVLESSPATH;
		edgetunnelTrojanPATH = url.searchParams.get('trojan_path') || env.EDGETUNNEL_TROJAN_PATH || edgetunnelTrojanPATH;
		edgetunnelProtocol = url.searchParams.get('protocol') || env.EDGETUNNEL_PROTOCOL || edgetunnelProtocol;

		addrSets = env.ADDR_SETS || addrSets;

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

async function parseNodesFromSubLink(links, concurrencyLimit = 5) {
	const regex = /(vless|trojan):\/\/.*?@((?:\d{1,3}\.){3}\d{1,3}|\[?[0-9a-fA-F:]+\]?)(?::(\d+))?.*?#(.*)/;
	const allNodes = [];

	async function fetchAndParse(link) {
		try {
			const response = await fetch(link);
			const lines = atob(await response.text())
				.trim()
				.split('\n');
			lines.forEach((line) => {
				const match = line.match(regex);
				if (!match) return;
				const [_, protocol, address, port, name] = match;
				allNodes.push({ protocol, address, port, name });
			});
		} catch (error) {
			console.log(`Error fetching or parsing link: ${link}`);
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
	allNodes.forEach((node) => uniqueNodes.set(`${node.protocol}:${node.address}`, node));
	return Array.from(uniqueNodes.values());
}

function parseNodesFromAddress(addresses) {
	const allNodes = [];

	const regex = /^((?<protocol>\w+):)?(?<ip>(\d{1,3}\.){3}\d{1,3}|\[[0-9a-fA-F:]+\])(:(?<port>\d+))?(#(?<name>.*))?$/;
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

function parseNodesFromPrivateURIs(uris) {
	const allNodes = uris.map((uri) => {
		const url = new URL(uri);
		const [uuid, addressWithPort] = url.username ? [url.username, url.host] : url.host.split('@');
		const [address, port] = addressWithPort.split(':');

		return {
			protocol: url.protocol.slice(0, -1),
			uuid: uuid || null,
			address: address || null,
			port: port ? parseInt(port, 10) : null,
			name: url.hash.slice(1),
			host: url.searchParams.get('host') || null,
			path: url.searchParams.get('path') || null,
			sni: url.searchParams.get('sni') || null,
		};
	});

	return allNodes;
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
	const rawAddr = JSON.parse(addrSets);

	let nodesFromLinks = [];
	let nodesFromAddresses = [];
	let nodesFromDomains = [];
	let nodesFromPrivateURIs = [];

	if (rawAddr.links && rawAddr.links.length > 0) {
		nodesFromLinks = await parseNodesFromSubLink(rawAddr.links);
	}
	if (rawAddr.addresses && rawAddr.addresses.length > 0) {
		nodesFromAddresses = parseNodesFromAddress(rawAddr.addresses);
	}
	if (rawAddr.domains && rawAddr.domains.length > 0) {
		nodesFromDomains = parseNodesFromDomain(rawAddr.domains);
	}
	if (rawAddr.privates && rawAddr.privates.length > 0) {
		nodesFromPrivateURIs = parseNodesFromPrivateURIs(rawAddr.privates);
	}

	switch (options.clienttype) {
		case 'singbox':
			return getSingBoxSubConfig(options, nodesFromLinks, nodesFromAddresses, nodesFromDomains, nodesFromPrivateURIs);

		default:
			return getDefaultSubConfig(options, nodesFromLinks, nodesFromAddresses, nodesFromDomains, nodesFromPrivateURIs);
	}
}

async function getDefaultSubConfig(options, nodesFromLinks, nodesFromAddresses, nodesFromDomains, nodesFromPrivateURIs) {
	const uniqueNodes = new Map();

	nodesFromLinks.forEach((node) => uniqueNodes.set(`${node.protocol}:${node.address}`, node));
	nodesFromAddresses.forEach((node) => uniqueNodes.set(`${node.protocol}:${node.address}`, node));
	nodesFromDomains.forEach((node) => uniqueNodes.set(`${node.protocol}:${node.address}`, node));
	nodesFromPrivateURIs.forEach((node) => uniqueNodes.set(`${node.protocol}:${node.address}`, node));

	const filteredNodes = Array.from(uniqueNodes.values()).filter((node) => {
		if (cfHTTPPorts.has(node.port)) return false;
		if (options.cfport === '1' && !cfHTTPSPorts.has(node.port)) return false;
		if (options.addrtype && !options.addrtype.split(',').includes(getAddressType(node.address))) return false;
		return true;
	});

	const configs = await Promise.all(
		filteredNodes.map((node) => {
			const uuid = node.uuid || edgetunnelUUID;
			const sni = node.sni || edgetunnelHost;
			const path = encodeURIComponent(node.path || (node.protocol === 'vless' ? edgetunnelVLESSPATH : edgetunnelTrojanPATH));
			const host = node.host || edgetunnelHost;

			const userInfo = `${uuid}${atob('QA==')}${node.address}:${node.port}`;
			switch (node.protocol) {
				case 'vless':
					return `${node.protocol}://${userInfo}/?security=tls&sni=${sni}&fp=chrome&type=ws&path=${path}&host=${host}#${node.name}`;
				case 'trojan':
					return `${node.protocol}://${userInfo}/?security=tls&sni=${sni}&fp=chrome&type=ws&path=${path}&host=${host}#${node.name}`;
				case 'hysteria2':
					return `${node.protocol}://${userInfo}/?sni=${sni}&insecure=1#${node.name}`;
				default:
					return '';
			}
		})
	);
	return options.base64 === '0' ? configs.join('\n') : btoa(configs.join('\n'));
}

function node2SingBoxOutbound(node) {
	const uuid = node.uuid || edgetunnelUUID;
	const sni = node.sni || edgetunnelHost;
	const path = node.path || (node.protocol === 'vless' ? edgetunnelVLESSPATH : edgetunnelTrojanPATH);
	const host = node.host || edgetunnelHost;

	switch (node.protocol) {
		case 'vless':
			return {
				type: node.protocol,
				tag: node.name,
				server: node.address,
				server_port: parseInt(node.port, 10),
				uuid: uuid,
				tls: {
					enabled: true,
					server_name: sni,
					insecure: true,
				},
				transport: {
					type: 'ws',
					path: path,
					max_early_data: 2048,
					early_data_header_name: 'Sec-WebSocket-Protocol',
					headers: { host: host },
				},
			};
		case 'trojan':
			return {
				type: node.protocol,
				tag: node.name,
				server: node.address,
				server_port: parseInt(node.port, 10),
				password: uuid,
				tls: {
					enabled: true,
					server_name: sni,
					insecure: true,
				},
				transport: {
					type: 'ws',
					path: path,
					max_early_data: 2048,
					early_data_header_name: 'Sec-WebSocket-Protocol',
					headers: { host: host },
				},
			};
		case 'hysteria2':
			return {
				type: node.protocol,
				tag: node.name,
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
		default:
			break;
	}
}

async function getSingBoxSubConfig(options, nodesFromLinks, nodesFromAddresses, nodesFromDomains, nodesFromPrivateURIs) {
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
				address: '172.18.0.1/30',
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
				{ ip_is_private: true, outbound: 'direct' },
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
				}
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

	const private_outbounds = [];
	nodesFromPrivateURIs.forEach((node) => private_outbounds.push(node2SingBoxOutbound(node)));
	singboxSubConfig.outbounds.push(...private_outbounds);

	const domain_outbounds = [];
	nodesFromDomains.forEach((node) => domain_outbounds.push(node2SingBoxOutbound(node)));
	singboxSubConfig.outbounds.push(...domain_outbounds);

	const address_outbounds = [];
	nodesFromAddresses.forEach((node) => address_outbounds.push(node2SingBoxOutbound(node)));
	singboxSubConfig.outbounds.push(...address_outbounds);

	const ipGeolocationMap = new Map(
		(await batchQueryIPGeolocation([...nodesFromAddresses.map((node) => node.address), ...nodesFromLinks.map((node) => node.address)])).map(
			(node) => [node.query, node]
		)
	);

	const link_outbounds = [];
	nodesFromLinks.forEach((node) => {
		const ipGeo = ipGeolocationMap.get(node.address);
		if (ipGeo && ipGeo.status === 'success') {
			node.name = `${ipGeo.countryCode}_${ipGeo.regionName}_${node.address}`;
			link_outbounds.push(node2SingBoxOutbound(node));
		}
	});
	singboxSubConfig.outbounds.push(...link_outbounds);

	const selector_outbounds = [];
	singboxSubConfig.outbounds.push({
		type: 'selector',
		tag: '节点选择',
		outbounds: selector_outbounds,
	});

	if (domain_outbounds.length > 0) {
		singboxSubConfig.outbounds.push({
			type: 'urltest',
			tag: '优选域名',
			outbounds: domain_outbounds.map((outbound) => outbound.tag),
			interrupt_exist_connections: false,
		});
		selector_outbounds.push('优选域名');
	}

	if (address_outbounds.length > 0) {
		singboxSubConfig.outbounds.push({
			type: 'urltest',
			tag: '优选IP',
			outbounds: address_outbounds.map((outbound) => outbound.tag),
			interrupt_exist_connections: false,
		});
		selector_outbounds.push('优选IP');
	}

	if (link_outbounds.length > 0) {
		// HK
		const link_hk_outbounds = link_outbounds.filter((outbound) => outbound.tag.startsWith('HK_')).map((outbound) => outbound.tag);
		if (link_hk_outbounds.length > 0) {
			singboxSubConfig.outbounds.push({
				type: 'urltest',
				tag: '第三方优选-中国香港(HK)',
				outbounds: link_hk_outbounds,
				interrupt_exist_connections: false,
			});
			selector_outbounds.push('第三方优选-中国香港(HK)');
		}
		// US
		const link_us_outbounds = link_outbounds.filter((outbound) => outbound.tag.startsWith('US_')).map((outbound) => outbound.tag);
		if (link_us_outbounds.length > 0) {
			singboxSubConfig.outbounds.push({
				type: 'urltest',
				tag: '第三方优选-美国(US)',
				outbounds: link_us_outbounds,
				interrupt_exist_connections: false,
			});
			selector_outbounds.push('第三方优选-美国(US)');
		}
		// JP
		const link_jp_outbounds = link_outbounds.filter((outbound) => outbound.tag.startsWith('JP_')).map((outbound) => outbound.tag);
		if (link_jp_outbounds.length > 0) {
			singboxSubConfig.outbounds.push({
				type: 'urltest',
				tag: '第三方优选-日本(JP)',
				outbounds: link_jp_outbounds,
				interrupt_exist_connections: false,
			});
			selector_outbounds.push('第三方优选-日本(JP)');
		}
		// KR
		const link_kr_outbounds = link_outbounds.filter((outbound) => outbound.tag.startsWith('KR_')).map((outbound) => outbound.tag);
		if (link_kr_outbounds.length > 0) {
			singboxSubConfig.outbounds.push({
				type: 'selector',
				tag: '第三方优选-韩国(KR)',
				outbounds: link_kr_outbounds,
			});
			selector_outbounds.push('第三方优选-韩国(KR)');
		}
		// Others
		const link_others_outbounds = link_outbounds
			.filter(
				(outbound) =>
					!outbound.tag.startsWith('HK_') &&
					!outbound.tag.startsWith('US_') &&
					!outbound.tag.startsWith('JP_') &&
					!outbound.tag.startsWith('KR_')
			)
			.map((outbound) => outbound.tag);
		if (link_others_outbounds.length > 0) {
			singboxSubConfig.outbounds.push({
				type: 'selector',
				tag: '第三方优选-其他',
				outbounds: link_others_outbounds,
			});
			selector_outbounds.push('第三方优选-其他');
		}
	}

	if (private_outbounds.length > 0) {
		singboxSubConfig.outbounds.push({
			type: 'selector',
			tag: '自建节点',
			outbounds: private_outbounds.map((outbound) => outbound.tag),
		});
		selector_outbounds.push('自建节点');
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

    `.trim();
}
