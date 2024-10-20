let edgetunnelUUID = '9e57b9c1-79ce-4004-a8ea-5a8e804fda51';
let edgetunnelHost = 'your.edgetunnel.host.com';
let edgetunnelPATH = '/?ed=2048';

let addrSets = `
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
`;

const cfHTTPPorts = new Set(['80', '8080', '8880', '2052', '2082', '2086', '2095']);
const cfHTTPSPorts = new Set(['443', '2053', '2083', '2087', '2096', '8443']);

export default {
	async fetch(request, env, ctx) {
		const url = new URL(request.url);

		edgetunnelUUID = env.EDGETUNNEL_UUID || edgetunnelUUID;
		edgetunnelHost = url.searchParams.get('host') || env.EDGETUNNEL_HOST || edgetunnelHost;
		edgetunnelPATH = url.searchParams.get('path') || env.EDGETUNNEL_PATH || edgetunnelPATH;

		addrSets = env.ADDR_SETS || addrSets;

		const options = {
			addrtype: url.searchParams.get('addrtype'),
			cfport: url.searchParams.get('cfport'),
			base64: url.searchParams.get('base64')
		}

		switch (url.pathname) {
			case `/sub/${edgetunnelUUID}`: // uuid as the default sub passwd
				return new Response(await getSubConfig(options));
			default:
				return new Response(getUsage(request));
		}
	},
};

async function getSubConfig(options) {
	const uniqueNodes = new Map();
	const rawAddr = JSON.parse(addrSets);

	if (rawAddr.links && rawAddr.links.length > 0) {
		const nodesFromLinks = await parseNodesFromSubLink(rawAddr.links);
		nodesFromLinks.forEach(node => uniqueNodes.set(`${node.protocol}:${node.address}`, node));
	}
	if (rawAddr.addresses && rawAddr.addresses.length > 0) {
		const nodesFromAddresses = await parseNodesFromAddress(rawAddr.addresses);
		nodesFromAddresses.forEach(node => uniqueNodes.set(`${node.protocol}:${node.address}`, node));
	}
	if (rawAddr.domains && rawAddr.domains.length > 0) {
		const nodesFromDomains = await parseNodesFromDomain(rawAddr.domains);
		nodesFromDomains.forEach(node => uniqueNodes.set(`${node.protocol}:${node.address}`, node));
	}

	const filteredNodes = Array.from(uniqueNodes.values()).filter(node => {
		// force filter http prot
		if (cfHTTPPorts.has(node.port)) return false;

		if (options.cfport === '1' && !cfHTTPSPorts.has(node.port)) return false;
		if (options.addrtype && !options.addrtype.split(',').includes(getAddressType(node.address))) return false;

		return true;
	});

	const configs = await Promise.all(filteredNodes.map(node => getSubConfigTemplate(node)));
	return options.base64 === '0' ? configs.join('\n') : btoa(configs.join('\n'));
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

function getSubConfigTemplate(node) {
	const finalAddress = node.address || edgetunnelHost;
	const finalPort = node.port || 443;

	const commonParams = `?security=tls&sni=${edgetunnelHost}&fp=random&alpn=h3&type=ws&path=${encodeURIComponent(edgetunnelPATH)}`;
	const userInfo = `${edgetunnelUUID}${atob('QA==')}${finalAddress}:${finalPort}`;

	switch (node.protocol) {
		case 'vless':
			return `${node.protocol}://${userInfo}${commonParams}&encryption=none&host=${edgetunnelHost}#${node.name}`;
		case 'trojan':
			return `${node.protocol}://${userInfo}${commonParams}#${node.name}`;
		default:
			return '';
	}
}

async function parseNodesFromSubLink(links, concurrencyLimit = 5) {
	const regex = /(vless|trojan):\/\/.*?@((?:\d{1,3}\.){3}\d{1,3}|\[?[0-9a-fA-F:]+\]?)(?::(\d+))?.*?#(.*)/;
	const allNodes = [];

	async function fetchAndParse(link) {
		try {
			const response = await fetch(link);
			const lines = atob(await response.text()).trim().split('\n');
			lines.forEach(line => {
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
		const batch = links.slice(i, i + concurrencyLimit).map(link => fetchAndParse(link));
		pool.push(Promise.all(batch)); // Process batch in parallel
	}

	await Promise.all(pool);

	return allNodes;
}

async function parseNodesFromAddress(addresses) {
	const allNodes = [];

	const regex = /^(?<ip>(\d{1,3}\.){3}\d{1,3}|\[[0-9a-fA-F:]+\])(:(?<port>\d+))?(#(?<name>.*))?$/;
	addresses.forEach(address => {
		const match = address.match(regex);
		if (match) {
			const { ip, port, name } = match.groups;
			const node = {
				protocol: 'vless',
				address: ip,
				port: port || '443',
				name: name || ip
			};
			allNodes.push(node);
		}
	});

	return allNodes;
}

async function parseNodesFromDomain(domains) {
	const allNodes = [];

	domains.forEach(domain => {
		const [domainPart, portPart] = domain.split(':');

		const node = {
			protocol: 'vless',
			address: domainPart,
			port: portPart || '443',
			name: domainPart
		};

		allNodes.push(node);
	});

	return allNodes;
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
- path (optional)
    Path to specify custom path for your edgetunnel (default is /?ed=2048 ).
- addrtype (optional)
    Specify which address types to return (default is return all types):
    - (empty)      : return all address types (ipv4, ipv6, and domain).
    - Combinations : You can combine values, e.g., 'ipv4,ipv6' to return both IPv4 and IPv6 addresses.
- cfport (optional)
    Specify if only return cloudflare standard ports (1 for yes, 0 for no, default is 0).
- base64 (optional)
    Specify if the output should be base64 encoded (1 for yes, 0 for no, default is 1).

Example usage:

1. Basic subscription:
   ${url.protocol}//${currentHost}/sub/9e57b9c1-79ce-4004-a8ea-5a8e804fda51

2. With parameters:
   ${url.protocol}//${currentHost}/sub/9e57b9c1-79ce-4004-a8ea-5a8e804fda51?host=example.com&path=/custom/path?ed=2048&addrtype=ip&cfport=1&base64=1

    `.trim();
}
