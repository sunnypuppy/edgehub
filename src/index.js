let edgetunnelUUID = '9e57b9c1-79ce-4004-a8ea-5a8e804fda51';
let edgetunnelHost = 'your.edgetunnel.host.com';
let edgetunnelVLESSPATH = '/?ed=2048';
let edgetunnelTrojanPATH = '/?ed=2048';
let edgetunnelProtocol = 'vless';

const cfHTTPPorts = new Set(['80', '8080', '8880', '2052', '2082', '2086', '2095']);
const cfHTTPSPorts = new Set(['443', '2053', '2083', '2087', '2096', '8443']);

let nodeAggConfig = {};

export default {
	async fetch(request, env, ctx) {
		try {
			const url = new URL(request.url);

			edgetunnelUUID = env.EDGETUNNEL_UUID || edgetunnelUUID;
			edgetunnelHost = url.searchParams.get('host') || env.EDGETUNNEL_HOST || edgetunnelHost;
			edgetunnelVLESSPATH = url.searchParams.get('vless_path') || env.EDGETUNNEL_VLESS_PATH || edgetunnelVLESSPATH;
			edgetunnelTrojanPATH = url.searchParams.get('trojan_path') || env.EDGETUNNEL_TROJAN_PATH || edgetunnelTrojanPATH;
			edgetunnelProtocol = url.searchParams.get('protocol') || env.EDGETUNNEL_PROTOCOL || edgetunnelProtocol;

			nodeAggConfig = env.NODE_AGG_CONFIG && JSON.parse(env.NODE_AGG_CONFIG);

			const options = {
				addrtype: url.searchParams.get('addrtype'),
				cfport: url.searchParams.get('cfport'),
				base64: url.searchParams.get('base64'),
				clienttype: url.searchParams.get('client'),
			};

			switch (url.pathname) {
				case `/sub/${edgetunnelUUID}`: // uuid as the default sub passwd
					return new Response(await getSubConfig(options));
				case `/sub/${edgetunnelUUID}/config`:
					return new Response(renderConfigManagerHTML(nodeAggConfig), { headers: { 'Content-Type': 'text/html' } });
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

async function parseNodesFromSubLink(links, concurrencyLimit = 5) {
	const allNodes = [];

	async function fetchAndParse(link) {
		try {
			const response = await fetch(link.url, { headers: link.headers });
			const lines = atob(await response.text())
				.trim()
				.split('\n');
			allNodes.push(...parseNodesFromURIs(lines, link.replace_backend));
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

function parseNodesFromURIs(uris, replace_backend = false) {
	return uris
		.map((uri) => {
			if (!uri.trim()) return null;
			try {
				const url = new URL(uri);
				const [uuid, addressWithPort] = url.username ? [url.username, url.host] : url.host.split('@');
				const lastColonIndex = addressWithPort.lastIndexOf(':');
				const address = addressWithPort.slice(0, lastColonIndex);
				const port = parseInt(addressWithPort.slice(lastColonIndex + 1), 10);
				return {
					protocol: url.protocol.slice(0, -1),
					address: address || null,
					port: port ? parseInt(port, 10) : null,
					name: url.hash ? decodeURIComponent(url.hash.slice(1)) : null,

					uuid: replace_backend ? null : uuid,
					host: replace_backend ? null : url.searchParams.get('host'),
					path: replace_backend ? null : url.searchParams.get('path'),
					sni: replace_backend ? null : url.searchParams.get('sni'),
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
			case 'raw_uri':
				node = parseNodesFromURIs(group.datas);
				node && nodes.push(...node);
				break;
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
				console.warn(`Unsupported parse type: ${group.parse_type}`);
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
	return options.base64 === '0' ? configs.join('\n') : Buffer.from(configs.join('\n'), 'utf-8').toString('base64');
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
				{ tag: 'google', address: 'udp://8.8.8.8' },
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
		const group_outbounds = nodes.map(node2SingBoxOutbound);
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

function renderConfigManagerHTML(configData) {
	return `
	<!DOCTYPE html>
	<html lang="zh">
		<head>
			<meta charset="UTF-8" />
			<meta name="viewport" content="width=device-width, initial-scale=1.0" />
			<title>配置管理</title>
			<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" />
			<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
			<style>
				body {
					padding: 20px;
				}
				pre {
					white-space: pre-wrap;
					word-wrap: break-word;
				}
				.table-container {
					max-height: 500px;
					overflow-y: auto;
				}
				#jsonDetail {
					white-space: pre;
					overflow-x: auto;
				}
				tr {
					cursor: pointer;
				}
				tr.dragging {
					opacity: 0.5;
				}
			</style>
		</head>
		<body>
			<div class="container">
				<h2 class="mb-4">配置管理</h2>

				<div class="mb-3">
					<button class="btn btn-primary me-2" onclick="addConfig()">新增配置</button>
					<button class="btn btn-warning me-2" onclick="resetConfig()">重置配置</button>
					<button id="exportConfigButton" class="btn btn-success me-2" onclick="exportConfigToClipboard()">导出配置</button>
				</div>

				<div class="table-container">
					<table class="table table-bordered">
						<thead class="table-dark">
							<tr>
								<th>组名</th>
								<th>解析类型</th>
								<th>出站类型</th>
								<th>配置详情</th>
								<th>操作</th>
							</tr>
						</thead>
						<tbody id="configTable" ondragover="handleDragOver(event)" ondrop="handleDrop(event)"></tbody>
					</table>
				</div>
			</div>

			<div class="modal fade" id="jsonModal" tabindex="-1">
				<div class="modal-dialog modal-lg">
					<div class="modal-content">
						<div class="modal-header">
							<h5 class="modal-title">完整 JSON 配置</h5>
							<button type="button" class="btn-close" data-bs-dismiss="modal"></button>
						</div>
						<div class="modal-body">
							<pre id="jsonDetail"></pre>
						</div>
					</div>
				</div>
			</div>

			<div class="modal fade" id="editModal" tabindex="-1">
				<div class="modal-dialog modal-lg">
					<div class="modal-content">
						<div class="modal-header">
							<h5 class="modal-title">编辑配置</h5>
							<button type="button" class="btn-close" data-bs-dismiss="modal"></button>
						</div>
						<div class="modal-body">
							<label for="editGroupName">组名：</label>
							<input type="text" id="editGroupName" class="form-control mb-2" />

							<label for="editParseType">解析类型：</label>
							<select id="editParseType" class="form-control mb-2" onchange="updateEditModalFields()">
								<option value="raw_uri">raw_uri</option>
								<option value="sub_link">sub_link</option>
								<option value="cf_prefer_ip">cf_prefer_ip</option>
								<option value="cf_prefer_domain">cf_prefer_domain</option>
							</select>

							<label for="outboundsTypeSelector">出站类型：</label>
							<div id="editOutboundsType" class="form-control">
								<label class="me-3"> <input type="radio" id="outboundsTypeSelector" name="outboundsType" value="selector" /> selector </label>
								<label> <input type="radio" id="outboundsTypeUrlTest" name="outboundsType" value="urltest" /> urltest </label>
							</div>

							<div id="editFields"></div>
						</div>
						<div class="modal-footer">
							<button type="button" class="btn btn-secondary" data-bs-dismiss="modal">取消</button>
							<button type="button" class="btn btn-success" onclick="saveConfig()">保存</button>
						</div>
					</div>
				</div>
			</div>

			<script>
				let configs = ${JSON.stringify(configData)} || {};

				let currentEditGroup = null;

				function renderTable() {
					const tableBody = document.getElementById('configTable');
					const exportButton = document.getElementById('exportConfigButton');
					tableBody.innerHTML = '';

					if (Object.keys(configs).length === 0) {
						exportButton.disabled = true;

						const row = document.createElement('tr');
						const cell = document.createElement('td');

						const columnCount = tableBody.querySelector('thead tr') ? tableBody.querySelector('thead tr').children.length : 5;
						cell.colSpan = columnCount;
						cell.textContent = '没有配置信息';
						cell.style.textAlign = 'center';
						cell.style.color = '#888';
						cell.style.fontStyle = 'italic';
						cell.style.padding = '20px';

						row.appendChild(cell);
						tableBody.appendChild(row);
						return;
					}
					exportButton.disabled = false;

					Object.entries(configs).forEach(([groupName, config]) => {
						const row = document.createElement('tr');
						row.setAttribute('draggable', 'true');
						row.setAttribute('data-group', groupName);
						row.addEventListener('dragstart', handleDragStart);
						row.addEventListener('dragend', handleDragEnd);

						const nameCell = document.createElement('td');
						nameCell.textContent = groupName;

						const typeCell = document.createElement('td');
						typeCell.textContent = config.parse_type;

						const otypeCell = document.createElement('td');
						otypeCell.textContent = config.outbounds_type || 'selector';

						const previewCell = document.createElement('td');
						const previewJson = JSON.stringify(config, null, 4);
						previewCell.textContent = previewJson.length > 80 ? previewJson.substring(0, 80) + '...' : previewJson;

						const actionCell = document.createElement('td');

						const viewButton = document.createElement('button');
						viewButton.className = 'btn btn-info btn-sm me-2';
						viewButton.textContent = '查看';
						viewButton.onclick = () => showJsonDetail(previewJson);

						const editButton = document.createElement('button');
						editButton.className = 'btn btn-warning btn-sm me-2';
						editButton.textContent = '编辑';
						editButton.onclick = () => openEditModal(groupName, config);

						const deleteButton = document.createElement('button');
						deleteButton.className = 'btn btn-danger btn-sm me-2';
						deleteButton.textContent = '删除';
						deleteButton.onclick = () => {
							delete configs[groupName];
							renderTable();
						};

						actionCell.appendChild(viewButton);
						actionCell.appendChild(editButton);
						actionCell.appendChild(deleteButton);

						row.appendChild(nameCell);
						row.appendChild(typeCell);
						row.appendChild(otypeCell);
						row.appendChild(previewCell);
						row.appendChild(actionCell);

						tableBody.appendChild(row);
					});
				}

				function handleDragStart(event) {
					event.target.classList.add('dragging');
				}

				function handleDragEnd(event) {
					event.target.classList.remove('dragging');
				}

				function handleDragOver(event) {
					event.preventDefault();
					const draggingRow = document.querySelector('.dragging');
					const targetRow = event.target.closest('tr');
					if (targetRow && targetRow !== draggingRow) {
						const allRows = [...document.querySelectorAll('tbody tr')];
						const targetIndex = allRows.indexOf(targetRow);
						const draggingIndex = allRows.indexOf(draggingRow);
						if (targetIndex > draggingIndex) {
							targetRow.after(draggingRow);
						} else {
							targetRow.before(draggingRow);
						}
					}
				}

				function handleDrop(event) {
					event.preventDefault();
					const draggingRow = document.querySelector('.dragging');
					const groupName = draggingRow.getAttribute('data-group');
					const targetRow = event.target.closest('tr');
					if (targetRow) {
						const targetGroup = targetRow.getAttribute('data-group');
						if (groupName !== targetGroup) {
							const keys = Object.keys(configs);
							const draggingIndex = keys.indexOf(groupName);
							const targetIndex = keys.indexOf(targetGroup);

							const temp = configs[groupName];
							configs[groupName] = configs[targetGroup];
							configs[targetGroup] = temp;

							renderTable();
						}
					}
				}

				function showJsonDetail(json) {
					document.getElementById('jsonDetail').textContent = json;
					new bootstrap.Modal(document.getElementById('jsonModal')).show();
				}

				function openEditModal(groupName, config) {
					currentEditGroup = groupName;
					document.getElementById('editGroupName').value = groupName;
					document.getElementById('editParseType').value = config.parse_type;
					document.querySelector(
						\`#editOutboundsType input[name="outboundsType"][value="\${config.outbounds_type || 'selector'}"]\`
					).checked = true;

					updateEditModalFields();
					new bootstrap.Modal(document.getElementById('editModal')).show();
				}

				function updateEditModalFields() {
					const groupName = document.getElementById('editGroupName').value;
					const parseType = document.getElementById('editParseType').value;
					const config = configs[groupName];

					const fieldsContainer = document.getElementById('editFields');
					fieldsContainer.innerHTML = '';
					if (['raw_uri', 'cf_prefer_ip', 'cf_prefer_domain'].includes(parseType)) {
						const label = document.createElement('label');
						label.textContent = '数据 (JSON 数组):';
						label.htmlFor = 'editDatas';

						const textarea = document.createElement('textarea');
						textarea.id = 'editDatas';
						textarea.className = 'form-control mb-2';
						textarea.rows = 6;
						textarea.style.resize = 'vertical';
						textarea.style.whiteSpace = 'nowrap';
						textarea.style.overflowX = 'auto';
						if (config.datas) {
							textarea.value = JSON.stringify(config.datas, null, 4);
						}

						fieldsContainer.appendChild(label);
						fieldsContainer.appendChild(textarea);
					}

					if (['sub_link'].includes(parseType)) {
						// url
						const urlLabel = document.createElement('label');
						urlLabel.textContent = 'URL:';
						const urlInput = document.createElement('input');
						urlInput.id = 'editUrl';
						urlInput.type = 'text';
						urlInput.className = 'form-control mb-2';
						if (config.url) {
							urlInput.value = config.url;
						}
						fieldsContainer.appendChild(urlLabel);
						fieldsContainer.appendChild(urlInput);

						// headers
						const headersLabel = document.createElement('label');
						headersLabel.textContent = 'Headers (可选，键值对):';
						fieldsContainer.appendChild(headersLabel);
						const headersContainer = document.createElement('div');
						headersContainer.id = 'headersContainer';
						headersContainer.className = 'mb-2';
						if (config.headers) {
							Object.entries(config.headers).forEach(([key, value]) => {
								addHeaderRow(headersContainer, key, value);
							});
						}
						const addHeaderButton = document.createElement('button');
						addHeaderButton.type = 'button';
						addHeaderButton.className = 'btn btn-sm btn-primary mb-2';
						addHeaderButton.textContent = '添加 Header';
						addHeaderButton.onclick = () => addHeaderRow(headersContainer, '', '');
						fieldsContainer.appendChild(headersContainer);
						fieldsContainer.appendChild(addHeaderButton);

						// replace_backend
						const replaceBackendLabel = document.createElement('label');
						replaceBackendLabel.textContent = '启用后端替换:';
						replaceBackendLabel.style.display = 'block';
						fieldsContainer.appendChild(replaceBackendLabel);
						const replaceBackendContainer = document.createElement('div');
						replaceBackendContainer.className = 'form-check form-switch mb-2';
						const replaceBackendCheckbox = document.createElement('input');
						replaceBackendCheckbox.id = 'replaceBackend';
						replaceBackendCheckbox.type = 'checkbox';
						replaceBackendCheckbox.className = 'form-check-input';
						if (config.replace_backend) {
							replaceBackendCheckbox.checked = config.replace_backend;
						}
						replaceBackendContainer.appendChild(replaceBackendCheckbox);
						fieldsContainer.appendChild(replaceBackendContainer);
					}
				}
				function addHeaderRow(container, key = '', value = '') {
					const row = document.createElement('div');
					row.className = 'd-flex mb-2';

					const keyInput = document.createElement('input');
					keyInput.type = 'text';
					keyInput.className = 'form-control me-2';
					keyInput.placeholder = 'Header Key';
					keyInput.value = key;

					const valueInput = document.createElement('input');
					valueInput.type = 'text';
					valueInput.className = 'form-control me-2';
					valueInput.placeholder = 'Header Value';
					valueInput.value = value;

					const removeButton = document.createElement('button');
					removeButton.type = 'button';
					removeButton.className = 'btn btn-sm btn-danger';
					removeButton.textContent = '删除';
					removeButton.onclick = () => row.remove();

					row.appendChild(keyInput);
					row.appendChild(valueInput);
					row.appendChild(removeButton);

					container.appendChild(row);
				}

				function getHeadersFromInputs() {
					const headers = {};
					document.querySelectorAll('#headersContainer div').forEach((row) => {
						const inputs = row.querySelectorAll('input');
						if (inputs.length === 2) {
							const key = inputs[0].value.trim();
							const value = inputs[1].value.trim();
							if (key) headers[key] = value;
						}
					});
					return headers;
				}

				function saveConfig() {
					const newGroupName = document.getElementById('editGroupName').value;
					const newParseType = document.getElementById('editParseType').value;
					const newOutboundsType = document.querySelector('#editOutboundsType input[name="outboundsType"]:checked')?.value;
					try {
						const newConfig = { parse_type: newParseType, outbounds_type: newOutboundsType };
						if (newParseType === 'raw_uri' || newParseType === 'cf_prefer_ip' || newParseType === 'cf_prefer_domain') {
							newConfig.datas = JSON.parse(document.getElementById('editDatas').value || '[]');
						}
						if (newParseType === 'sub_link') {
							newConfig.url = document.getElementById('editUrl').value;
							const headers = getHeadersFromInputs();
							if (Object.keys(headers).length > 0) {
								newConfig.headers = headers;
							}
							if (document.getElementById('replaceBackend').checked) {
								newConfig.replace_backend = true;
							}
						}
						if (currentEditGroup !== newGroupName) delete configs[currentEditGroup];
						configs[newGroupName] = newConfig;
						renderTable();
						bootstrap.Modal.getInstance(document.getElementById('editModal')).hide();
					} catch (e) {
						alert('保存配置时出错：' + e.message);
					}
				}

				function addConfig() {
					const newGroupName = prompt('请输入配置组名');
					if (newGroupName) {
						configs[newGroupName] = { parse_type: 'raw_uri', datas: [] };
						renderTable();
					}
				}

				function resetConfig() {
					configs = ${JSON.stringify(configData)};
					renderTable();
				}

				function exportConfigToClipboard() {
					const jsonConfig = JSON.stringify(configs, null, 4);
					navigator.clipboard
						.writeText(jsonConfig)
						.then(() => {
							alert('配置已复制到剪切板！');
						})
						.catch((err) => {
							alert('复制到剪切板失败: ' + err);
						});
				}

				renderTable();
			</script>
		</body>
	</html>
	`;
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
