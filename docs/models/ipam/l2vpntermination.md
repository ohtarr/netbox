# L2VPN Termination

A L2VPN Termination is the termination point of a L2VPN.  Certain types of L2VPNs may only have 2 termination points (point-to-point) while others may have many terminations (multipoint).

Each termination consists of a L2VPN it is a member of as well as the connected endpoint which can be an interface or a VLAN.

The following types of L2VPNs are considered point-to-point:

* VPWS
* EPL
* EP-LAN
* EP-TREE

!!! note
    Choosing any of the above types will result in only being able to add 2 terminations to a given L2VPN.