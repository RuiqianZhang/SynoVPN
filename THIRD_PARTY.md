# Third-party software

The portal/control code is MIT licensed. The strongSwan daemon is a separate
process and retains its own GPL-2.0-or-later license and OpenSSL exception.

| Component | Source / version | License information |
| --- | --- | --- |
| strongSwan | https://download.strongswan.org/strongswan-6.1.0.tar.gz | Upstream COPYING and LICENSE, included by runtime builder |
| govici | github.com/strongswan/govici v0.8.2 | MIT, copied into the SPK licenses/go directory by build.py |
| go-pkcs12 | software.sslmate.com/src/go-pkcs12 v0.7.4 | BSD-3-Clause; actual upstream license included by dependency collection |
| modernc SQLite and transitive Go modules | Versions pinned in go.mod/go.sum | See generated build/licenses and module upstream notices |
| OpenSSL / musl | Alpine build dependencies | Respective upstream licenses; included by runtime builder |

The runtime source tarball SHA-256 is:
`d9484eea319481bda86f992fa69cbdbdd9c0d6f8b9a4bd793a7df45c0760d963`.

The SPK builder includes the strongSwan corresponding source tarball and build
recipe. A distributor must retain these notices, fulfill applicable source and
license obligations, and review dependency/security updates before a release.

No proprietary Synology binary is redistributed. authenticate.cgi is invoked
from its existing installation on the user's DSM system.
