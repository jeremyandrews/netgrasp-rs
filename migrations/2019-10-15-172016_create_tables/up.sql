CREATE TABLE IF NOT EXISTS arp (
	arp_id INTEGER NOT NULL PRIMARY KEY,
	src_mac_id INTEGER NOT NULL,
	src_ip_id INTEGER NOT NULL,
	tgt_ip_id INTEGER NOT NULL,
	interface TEXT NOT NULL,
	host_name TEXT NOT NULL,
	custom_name TEXT NOT NULL,
	vendor_name TEXT NOT NULL,
	vendor_full_name TEXT NOT NULL,
	src_mac TEXT NOT NULL,
	src_ip TEXT NOT NULL,
	tgt_mac TEXT NOT NULL,
	tgt_ip TEXT NOT NULL,
	operation INTEGER NOT NULL,
	matched INTEGER NOT NULL,
	created INTEGER NOT NULL,
	updated INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idxarp_int_src_tgt_op ON arp (interface, src_mac_id, src_ip_id, tgt_ip_id, operation);

CREATE TABLE IF NOT EXISTS event (
	event_id INTEGER NOT NULL PRIMARY KEY,
	mac_id INTEGER NOT NULL,
	ip_id INTEGER NOT NULL,
	vendor_id INTEGER NOT NULL,
	interface TEXT NOT NULL,
	network TEXT NOT NULL,
	description TEXT NOT NULL,
	processed INTEGER NOT NULL,
	created INTEGER NOT NULL,
	updated INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS ip (
	ip_id INTEGER NOT NULL PRIMARY KEY,
	mac_id INTEGER NOT NULL,
	address TEXT NOT NULL,
	host_name TEXT NOT NULL,
	custom_name TEXT NOT NULL,
	created INTEGER NOT NULL,
	updated INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idxip_address_macid ON ip (address, mac_id);

CREATE TABLE IF NOT EXISTS mac (
	mac_id  INTEGER NOT NULL PRIMARY KEY,
	vendor_id  INTEGER NOT NULL,
	address TEXT NOT NULL,
	is_self INTEGER NOT NULL,
	created INTEGER NOT NULL,
	updated INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idxmac_address ON mac (address);

CREATE TABLE IF NOT EXISTS vendor(
	vendor_id INTEGER NOT NULL PRIMARY KEY,
	name TEXT NOT NULL,
	full_name TEXT NOT NULL,
	created INTEGER NOT NULL,
	updated INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idxname_fullname ON vendor (name, full_name);
