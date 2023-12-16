# necrotelicomnicon - Dynamic DNS web service
# Copyright 2023  Simon Arlott
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import cbor2
import fcntl
import ipaddress
import os
import psycopg2.extras
import psycopg2.pool
import re
import subprocess
import webob
import webob.exc
import yaml

with open("config", "r") as f:
	config = yaml.safe_load(f)

max_pool = 20

pool = psycopg2.pool.ThreadedConnectionPool(5, max_pool, config["dsn"], connection_factory=psycopg2.extras.RealDictConnection)

def getconn(pool, max_conns):
	attempts = max_conns + 1
	conn = None
	while attempts > 0:
		conn = pool.getconn()
		try:
			conn.isolation_level
			return conn
		except psycopg2.OperationalError:
			pool.putconn(conn, close=True)
			attempts -= 1
	return conn

def rewrite(filename, hostname, ip4, ip6):
	with open(filename, "r") as f:
		data = f.read()

	lines = data.rstrip("\n").split("\n")
	new_lines = []
	hostname = hostname.lower()
	prefix4 = f"{hostname} A "
	record4 = f"{hostname} A {ip4}" if ip4 else ""
	prefix6 = f"{hostname} AAAA "
	record6 = f"{hostname} AAAA {ip6}" if ip6 else ""

	for line in lines:
		# Allow existing A record once
		if record4 and line == record4:
			record4 = ""
			new_lines.append(line)
		# Allow existing AAAA record once
		elif record6 and line == record6:
			record6 = ""
			new_lines.append(line)
		# Remove old A/AAAA records
		elif not line.startswith(prefix4) and not line.startswith(prefix6):
			new_lines.append(line)

	# Add new A record
	if record4:
		new_lines.append(record4)

	# Add new AAAA record
	if record6:
		new_lines.append(record6)

	new_data = "\n".join(new_lines) + "\n"
	if data == new_data:
		return

	with open(f"{filename}~", "w") as f:
		f.write(new_data)

	os.rename(f"{filename}~", filename)

def update(origin, hostname, ip4, ip6):
	cwd = config["git"]

	with open("lock", "w") as lock:
		fcntl.flock(lock, fcntl.LOCK_EX)
		try:
			if subprocess.run(["git", "reset", "--hard", "HEAD"], cwd=cwd).returncode != 0:
				return "Git reset failed"

			if subprocess.run(["git", "pull", "--rebase"], cwd=cwd).returncode != 0:
				return "Git pull failed"

			rewrite(f"{config['git']}/{config['zone']}", hostname, ip4, ip6)

			if subprocess.run(["git", "diff-files", "--quiet", "--", config["zone"]], cwd=cwd).returncode != 0:
				if subprocess.run(["git", "commit", "-a", "-m", origin], cwd=cwd).returncode != 0:
					return "Git commit failed"

			if subprocess.run(["git", "push"], cwd=cwd).returncode != 0:
				return "Git push failed"

			return ""
		finally:
			fcntl.flock(lock, fcntl.LOCK_UN)

def application(environ, start_response):
	req = webob.Request(environ)
	res = webob.Response(content_type="application/cbor")

	error = ""
	data = None
	auth = False

	if not req.body:
		error = "No data"
	elif len(req.body) > 256:
		error = "Too much data"
	else:
		data = cbor2.loads(req.body)
	
	if error:
		pass
	elif not data:
		error = "Null data"
	elif not isinstance(data, dict):
		error = "Data is not a dict"
	elif "hostname" not in data:
		error = "No hostname"
	elif "password" not in data:
		error = "No password"
	elif not isinstance(data["hostname"], str):
		error = "Hostname is not a string"
	elif not isinstance(data["password"], str):
		error = "Password is not a string"
	elif "ip4" in data and not isinstance(data["ip4"], str):
		error = "IPv4 address is not a string"
	elif "ip6" in data and not isinstance(data["ip6"], str):
		error = "IPv6 address is not a string"

	if not error and "ip4" in data:
		try:
			data["ip4"] = str(ipaddress.IPv4Address(data["ip4"]))
		except Exception as e:
			error = f"Invalid IPv4 address: {e}"

	if not error and "ip6" in data:
		try:
			data["ip6"] = str(ipaddress.IPv6Address(data["ip6"]))
		except Exception as e:
			error = f"Invalid IPv6 address: {e}"

	if error:
		pass
	else:
		db = getconn(pool, max_pool)
		if db:
			try:
				c = db.cursor()
				c.execute("SELECT 1 FROM users WHERE hostname=%(hostname)s AND password=crypt(%(password)s, password)", data)
				auth = c.rowcount == 1
				db.commit()
				c.close()
				del c
			finally:
				pool.putconn(db)
		else:
			error = "Database unavailable"

	if error:
		pass
	elif auth:
		error = update(req.remote_addr, data["hostname"], data.get("ip4", None), data.get("ip6", None))
	else:
		error = "Invalid credentials"

	f = res.body_file
	if error:
		f.write(cbor2.dumps([False, error]))
	else:
		f.write(cbor2.dumps([True]))
	return res(environ, start_response)
