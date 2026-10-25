---
title: "Subnet Calculator: IPv4, IPv6, CIDR & VLSM"
description: "Calculate network, broadcast, host range, mask and wildcard for any IPv4 or IPv6 CIDR, split a block into equal or VLSM subnets. Runs in your browser."
intro: "A **subnet calculator** for IPv4 and IPv6: type an address with its prefix or mask and get the network, broadcast, usable host range, netmask, wildcard and host count instantly, with a binary view. A third tab splits a block into equal subnets or into VLSM subnets sized by host count."
date: 2026-10-25
lastmod: 2026-10-25
reviewed: false
keywords: ["subnet calculator", "cidr calculator", "ip subnet calculator", "ipv6 subnet calculator", "vlsm calculator", "subnet mask calculator", "wildcard mask calculator", "network address calculator"]
tags: ["networking", "developer-tools", "ipv4", "ipv6", "tool"]
app_category: "DeveloperApplication"
tool_file: "/tools/subnet-calculator/"
tool_title: "Subnet calculator for IPv4, IPv6 and VLSM"
tool_height: 900
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "On the **IPv4** tab, type an address with a prefix (`10.0.0.5/8`), a dotted netmask (`172.16.5.4 255.255.240.0`) or a Cisco-style wildcard (`192.168.1.1 0.0.0.255`). A bare address is treated as `/32`."
  - "Read the results as you type: network, broadcast, first and last usable host, netmask, wildcard, usable and total addresses, and the address type (private, public, CGNAT, link-local…)."
  - "Check the **Binary** table: the network bits are highlighted, the host bits are dimmed, so you can see exactly where the prefix cuts the address."
  - "On the **IPv6** tab, paste any full or compressed address with a prefix to get the RFC 5952 compressed form, the expanded form, the first and last address of the prefix and how many /64 networks it contains."
  - "On **Split (VLSM)**, enter the block to divide and choose **Into equal subnets** (how many) or **By hosts per subnet** (a list such as `100, 50, 20, 2`). Copy any value with its **Copy** button, or the whole plan with **Copy table**."
faq:
  - q: "Why does a /24 have 254 usable hosts and not 256?"
    a: "A /24 has 256 addresses, but the first one is the network address and the last one is the broadcast address. Neither can be assigned to a host, which leaves 254. The same rule (total minus two) applies to every prefix up to /30."
  - q: "How does the calculator handle /31 and /32?"
    a: "A /31 is treated as a point-to-point link as defined in RFC 3021: both addresses are usable and there is no broadcast. A /32 is a single host address, used for loopbacks, host routes and firewall rules. Older equipment that does not support RFC 3021 needs a /30 for a link instead."
  - q: "What is a wildcard mask?"
    a: "The bitwise inverse of the netmask: 255.255.255.0 becomes 0.0.0.255. Cisco ACLs and OSPF network statements use wildcards, where a 0 bit means \"must match\" and a 1 bit means \"any value\". You can type a wildcard directly in the IPv4 box and the calculator converts it to the prefix."
  - q: "What does VLSM mean and why are the biggest subnets placed first?"
    a: "Variable Length Subnet Masking lets each subnet have its own prefix, so a LAN of 100 hosts gets a /25 while a point-to-point link gets a /31. Allocating from the largest request to the smallest keeps every subnet aligned on its own boundary without wasting gaps; the results are then listed in the order you typed them."
  - q: "Why does splitting into 3 subnets give me 4?"
    a: "Equal splitting borrows host bits, and each borrowed bit doubles the number of subnets: 1 bit gives 2, 2 bits give 4. Three subnets therefore need 2 bits, which produces 4. Use the VLSM mode if you want exactly as many subnets as you ask for, each sized to its host count."
  - q: "Which IPv6 prefix should a LAN use?"
    a: "A /64. Stateless address autoconfiguration (SLAAC) and many IPv6 features assume a 64-bit interface identifier. Sites usually receive a /48 or /56 and carve it into /64s; the calculator shows how many /64 networks fit in the prefix you enter."
  - q: "Is anything I type sent to a server?"
    a: "No. All calculations are done by a small JavaScript module in your browser; the page makes no requests with your input, so it is safe to use with internal addressing plans."
---

## How it works

### IPv4 arithmetic

An IPv4 address is a 32-bit number. The calculator parses the four octets (rejecting values above 255 and ambiguous leading zeros such as `010`), builds the netmask from the prefix length by setting the top *n* bits, and then works with plain bitwise operations:

- **Network address** = address AND mask.
- **Wildcard** = NOT mask.
- **Broadcast address** = network OR wildcard.
- **Usable hosts** = 2^(32 − prefix) − 2, with the two exceptions described in the FAQ: a /31 has two usable addresses (RFC 3021) and a /32 has one.

When you type a dotted mask, it must be *contiguous*: ones followed by zeros. `255.255.240.0` is accepted as /20; `255.0.255.0` is rejected. If the value is not a valid netmask but is a valid wildcard (zeros followed by ones), it is read as a wildcard, so `0.0.15.255` also means /20.

The address type comes from the IANA special-purpose registries: RFC 1918 private ranges (10/8, 172.16/12, 192.168/16), shared address space for carrier-grade NAT (100.64/10, RFC 6598), loopback (127/8), link-local (169.254/16), the three documentation ranges, multicast (224/4) and reserved space.

### IPv6

IPv6 addresses are 128-bit numbers, held as JavaScript `BigInt`s so no precision is lost. The parser accepts the full form, `::` compression (only once per address), and an IPv4 tail such as `::ffff:192.0.2.1`. Output follows **RFC 5952**, the canonical text form: lowercase hex, no leading zeros in a group, and the longest run of two or more zero groups replaced by `::` (the leftmost one when two runs have the same length). A single zero group is never compressed.

For a prefix, the first address is the address AND the mask, the last address sets every host bit to one, and the size is 2^(128 − prefix). IPv6 has no broadcast, so there is no "minus two".

### Splitting a block

*Equal subnets* adds ⌈log₂ n⌉ bits to the prefix and lists every resulting subnet (up to 1,024 rows). *VLSM* computes, for each host count, the smallest prefix that fits it, sorts the requests from largest to smallest, and allocates each one at the next address aligned to its size. If a request does not fit in what is left, you get an error that names it instead of an overlapping plan.

## Use cases

- **Designing an addressing plan.** Split a /22 for a new office into user, voice, printer and management VLANs sized by headcount, then paste the table into your documentation.
- **Writing firewall rules and ACLs.** Get the exact network/prefix or wildcard for an object group, and check that a /20 really covers the range you think it does.
- **Troubleshooting.** Two hosts cannot talk to each other: put both addresses with their masks into the calculator and see whether they are actually in the same subnet.
- **Cloud networking.** Plan VPC and subnet CIDRs without overlaps, and remember that cloud providers reserve a few addresses per subnet on top of network and broadcast.
- **Learning and exams.** Check subnetting exercises for CCNA, Network+ or job interviews; the binary view shows why the answer is what it is.
