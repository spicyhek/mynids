# Same decoding as the sensor: keep in sync with homelab-infra k8s/daemonsets/zeek/local.zeek.
# K3s flannel uses the Linux VXLAN port, not the IANA 4789 Zeek registers by default.
redef PacketAnalyzer::VXLAN::vxlan_ports += { 8472/udp };
redef likely_server_ports += { 8472/udp };
