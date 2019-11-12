CREATE TABLE IF NOT EXISTS network_event (
	netevent_id INTEGER NOT NULL PRIMARY KEY,
	recent INTEGER NOT NULL,
	processed INTEGER NOT NULL,
	interface_id INTEGER NOT NULL,
	mac_id INTEGER NOT NULL,
	vendor_id INTEGER NOT NULL,
	ip_id INTEGER NOT NULL,
	tgt_mac_id INTEGER NOT NULL,
	tgt_vendor_id INTEGER NOT NULL,
	tgt_ip_id INTEGER NOT NULL,
	created INTEGER NOT NULL,
	updated INTEGER NOT NULL,
	FOREIGN KEY(interface_id) REFERENCES interface(interface_id),
	FOREIGN KEY(mac_id) REFERENCES mac(mac_id),
	FOREIGN KEY(vendor_id) REFERENCES vendor(vendor_id),
	FOREIGN KEY(ip_id) REFERENCES ip(ip_id)
);

CREATE TABLE IF NOT EXISTS interface (
	interface_id INTEGER NOT NULL PRIMARY KEY,
	label TEXT NOT NULL,
	address TEXT NOT NULL,
	created INTEGER NOT NULL,
	updated INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS mac (
	mac_id  INTEGER NOT NULL PRIMARY KEY,
	is_self INTEGER NOT NULL,
	vendor_id  INTEGER NOT NULL,
	address TEXT NOT NULL,
	created INTEGER NOT NULL,
	updated INTEGER NOT NULL,
	FOREIGN KEY(vendor_id) REFERENCES vendor(vendor_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS idxmac_address ON mac (address);

CREATE TABLE IF NOT EXISTS ip (
	ip_id INTEGER NOT NULL PRIMARY KEY,
	mac_id INTEGER NOT NULL,
	address TEXT NOT NULL,
	host_name TEXT NOT NULL,
	custom_name TEXT NOT NULL,
	created INTEGER NOT NULL,
	updated INTEGER NOT NULL,
	FOREIGN KEY(mac_id) REFERENCES mac(mac_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS idxip_address_macid ON ip (address, mac_id);

CREATE TABLE IF NOT EXISTS vendor (
	vendor_id INTEGER NOT NULL PRIMARY KEY,
	name TEXT NOT NULL,
	full_name TEXT NOT NULL,
	created INTEGER NOT NULL,
	updated INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idxname_fullname ON vendor (name, full_name);
