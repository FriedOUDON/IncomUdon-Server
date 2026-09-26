# Third-Party Licenses

The IncomUdon Relay source in this repository is licensed under the MIT
License in [`../LICENSE`](../LICENSE). This directory contains the license
texts and notices for third-party components included in supported Relay
builds.

| Component | License | Notice |
| --- | --- | --- |
| Go toolchain and standard library | BSD 3-Clause | [`Go.txt`](Go.txt) |

`Go.txt` applies to distributed Relay binaries built with Go. The Relay
forwards codec frames but does not link, bundle, or execute codec libraries.

Update this inventory and add the applicable upstream license text whenever a
new third-party component is distributed with a Relay binary or container
image.
