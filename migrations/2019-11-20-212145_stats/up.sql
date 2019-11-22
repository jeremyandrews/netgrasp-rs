CREATE TABLE IF NOT EXISTS stats (
	stats_id INTEGER NOT NULL PRIMARY KEY,
	mac_id INTEGER NOT NULL,
	ip_id INTEGER NOT NULL,
	period_date INTEGER NOT NULL,
	period_length INTEGER NOT NULL,
	period_number INTEGER NOT NULL,
	total INTEGER NOT NULL,
	different INTEGER NOT NULL,
	mean FLOAT NOT NULL,
	median FLOAT NOT NULL,
	created INTEGER NOT NULL,
	updated INTEGER NOT NULL,
	FOREIGN KEY(mac_id) REFERENCES mac(mac_id)
	FOREIGN KEY(ip_id) REFERENCES mac(ip_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS idxstats_mac_ip_datlennum ON stats (mac_id, ip_id, period_date, period_length, period_number)