#!/usr/bin/env python3
"""Disable per-socket UDP GRO for DSM kernels; keep UDP_ENCAP and authentication."""
from pathlib import Path
import sys
p = Path(sys.argv[1]) / 'src/libcharon/plugins/kernel_netlink/kernel_netlink_ipsec.c'
s = p.read_text()
old = """	type = 1;
	if (setsockopt(fd, SOL_UDP, UDP_GRO, &type, sizeof(type)) < 0)
	{
		DBG1(DBG_KNL, "unable to set UDP_GRO: %s", strerror(errno));
		return FALSE;
	}
"""
new = """	/* SynoVPN: DSM compatibility; preserve datagram boundaries for IKE. */
	DBG1(DBG_KNL, "SynoVPN: UDP GRO disabled for DSM compatibility");
"""
if new in s:
    print('UDP GRO compatibility patch already applied')
else:
    if s.count(old) != 1:
        raise SystemExit('Unexpected strongSwan source: refusing to patch')
    p.write_text(s.replace(old, new))
    print('Applied DSM UDP GRO compatibility patch')
