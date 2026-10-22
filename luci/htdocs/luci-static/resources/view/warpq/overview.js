'use strict';
'require view';
'require form';
'require rpc';
'require poll';
'require dom';
'require ui';

var callStatus = rpc.declare({ object: 'warpq', method: 'status' });
var callAccount = rpc.declare({ object: 'warpq', method: 'account' });
var callStart = rpc.declare({ object: 'warpq', method: 'start' });
var callStop = rpc.declare({ object: 'warpq', method: 'stop' });
var callRegister = rpc.declare({
	object: 'warpq',
	method: 'register',
	params: [ 'name' ]
});

function formatBytes(value) {
	var units = [ 'B', 'KiB', 'MiB', 'GiB', 'TiB' ];
	var n = parseInt(value) || 0;
	var unit = 0;

	while (n >= 1024 && unit < units.length - 1) {
		n /= 1024;
		unit++;
	}
	return (unit ? n.toFixed(2) : n) + ' ' + units[unit];
}

function formatUptime(value) {
	var seconds = parseInt(value) || 0;

	return '%t'.format(seconds);
}

function statusRows(status) {
	var state = status.state || 'stopped';
	var connected = (state == 'connected');
	var rows = [ [ _('State'),
		E('span', { 'class': connected ? 'label' : 'label warning' },
		  connected ? _('Connected') : (state == 'connecting' ? _('Connecting') : _('Stopped'))) ] ];

	if (status.registered === false)
		rows.push([ _('Device'), _('not registered yet') ]);

	if (state != 'stopped') {
		rows.push([ _('Transport'), status.transport || 'masque/http2' ]);
		rows.push([ _('Interface'), status.interface || '-' ]);
		rows.push([ _('Addresses'),
			    (status.ipv4 || '-') + ' / ' + (status.ipv6 || '-') ]);
		rows.push([ _('Endpoint'), status.endpoint || '-' ]);
		rows.push([ _('Routing'), status.routed ? _('all traffic') : _('interface only') ]);
		rows.push([ _('Uptime'), formatUptime(status.uptime) ]);
		rows.push([ _('Received'), '%s (%d %s)'.format(formatBytes(status.rx_bytes),
			    status.rx_packets || 0, _('packets')) ]);
		rows.push([ _('Sent'), '%s (%d %s)'.format(formatBytes(status.tx_bytes),
			    status.tx_packets || 0, _('packets')) ]);
		if (status.reconnects)
			rows.push([ _('Reconnects'), status.reconnects ]);
	}

	return rows;
}

function renderTable(status) {
	var table = E('table', { 'class': 'table' });

	statusRows(status).forEach(function(row) {
		table.appendChild(E('tr', { 'class': 'tr' }, [
			E('td', { 'class': 'td left', 'width': '33%' }, row[0]),
			E('td', { 'class': 'td left' }, row[1])
		]));
	});
	return table;
}

return view.extend({
	load: function() {
		return callStatus().catch(function() { return { state: 'stopped' }; });
	},

	render: function(status) {
		var self = this;
		var statusBox = E('div', {}, renderTable(status));
		var accountBox = E('div', { 'class': 'cbi-value-description' }, '');

		poll.add(function() {
			return callStatus().then(function(current) {
				dom.content(statusBox, renderTable(current));
			}).catch(function() {
				dom.content(statusBox, renderTable({ state: 'stopped' }));
			});
		}, 5);

		var buttons = E('div', { 'class': 'cbi-section' }, [
			E('button', {
				'class': 'cbi-button cbi-button-apply',
				'click': ui.createHandlerFn(self, function() {
					return callStart().then(function(res) {
						if (res && res.result == 'disabled')
							ui.addNotification(null,
								E('p', _('Tick "Start at boot", save, then start again.')),
								'warning');
						else
							ui.addNotification(null, E('p', _('Tunnel starting')), 'info');
					});
				})
			}, _('Start')),
			' ',
			E('button', {
				'class': 'cbi-button cbi-button-reset',
				'click': ui.createHandlerFn(self, function() {
					return callStop().then(function() {
						ui.addNotification(null, E('p', _('Tunnel stopped')), 'info');
					});
				})
			}, _('Stop')),
			' ',
			E('button', {
				'class': 'cbi-button cbi-button-action',
				'click': ui.createHandlerFn(self, function() {
					return callRegister('').then(function(res) {
						if (res && res.result == 'error')
							ui.addNotification(null,
								E('p', _('Registration failed: %s').format(res.message || '')),
								'error');
						else if (res && res.result == 'exists')
							ui.addNotification(null,
								E('p', _('This device is already registered')), 'info');
						else
							ui.addNotification(null,
								E('p', _('Registered a new WARP device')), 'info');
					});
				})
			}, _('Register device')),
			' ',
			E('button', {
				'class': 'cbi-button cbi-button-neutral',
				'click': ui.createHandlerFn(self, function() {
					return callAccount().then(function(account) {
						dom.content(accountBox, E('pre', {},
							Object.keys(account || {}).map(function(key) {
								return key + ': ' + account[key] + '\n';
							}).join('')));
					});
				})
			}, _('Show account'))
		]);

		var m = new form.Map('warpq');
		var s = m.section(form.NamedSection, 'config', 'warpq', _('Settings'));
		var o;

		s.anonymous = true;

		o = s.option(form.Flag, 'enabled', _('Start at boot'));
		o.rmempty = false;

		o = s.option(form.Value, 'interface', _('Interface'),
			_('Name of the TUN device to create.'));
		o.default = 'warp0';
		o.rmempty = false;

		o = s.option(form.Value, 'mtu', _('MTU'));
		o.datatype = 'range(576,1500)';
		o.default = '1280';

		o = s.option(form.Value, 'port', _('Endpoint port'),
			_('TCP port of the MASQUE endpoint.'));
		o.datatype = 'port';
		o.default = '443';

		o = s.option(form.Flag, 'default_route', _('Route all traffic'),
			_('Send everything through the tunnel using policy routing. The tunnel marks its own packets so they stay outside.'));
		o.default = '1';

		o = s.option(form.Flag, 'ipv6_endpoint', _('Use the IPv6 endpoint'),
			_('Reach the MASQUE endpoint over IPv6 instead of IPv4.'));
		o.default = '0';

		return m.render().then(function(mapEl) {
			return E([], [
				E('h2', {}, _('Cloudflare WARP')),
				E('div', { 'class': 'cbi-map-descr' },
				  _('A minimal WARP client speaking MASQUE (connect-ip over HTTP/2), exposed as a TUN device.')),
				E('div', { 'class': 'cbi-section' }, [
					E('h3', {}, _('Status')),
					statusBox,
					accountBox,
					buttons
				]),
				mapEl
			]);
		});
	}
});
