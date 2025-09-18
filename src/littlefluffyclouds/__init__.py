"""Little Fluffy Clouds: Gather a bunch of small adjacent networks into larger ones.

Example:
    >>> from ipaddress import IPv4Network as I
    >>> gather([I('10.0.8.0/24'), I('10.0.9.0/24'), I('10.0.10.0/24'), I('10.0.11.0/24')])
    [IPv4Network('10.0.8.0/22')]

Here, the 10.0.8.0/22 network covers exactly the same addresses as the 4 smaller networks.
"""

from argparse import ArgumentParser
from collections import defaultdict
from ipaddress import IPv4Network, IPv6Network, ip_network
from itertools import pairwise
from typing import overload


@overload
def dedupe(lst: list[IPv4Network]) -> list[IPv4Network]: ...
@overload
def dedupe(lst: list[IPv6Network]) -> list[IPv6Network]: ...
def dedupe(lst):
    """Return the unique, non-"covered" networks in the list."""
    if len(lst) < 2:
        return lst

    low = lst[0]
    out = [low]
    for high in lst[1:]:
        if high == low:
            # If the blocks are the same, ignore high.
            continue
        if high.subnet_of(low):
            # If high is inside low, ignore it. (Because of sorting, low can
            # never be inside high, as short prefixlens come before long
            # prefixlens.)
            continue
        low = high
        out.append(low)
    return out


@overload
def gather(lst: list[IPv4Network]) -> list[IPv4Network]: ...
@overload
def gather(lst: list[IPv6Network]) -> list[IPv6Network]: ...
def gather(lst):
    """Return the smallest number of networks that exactly cover the same ranges as the original list."""
    lst = sorted(lst)
    if len(lst) < 2:
        return lst

    # Group all the networks according to their prefixlength.
    bucket = defaultdict(set)
    a = lst
    a = dedupe(lst)
    for net in a:
        bucket[net.prefixlen].add(net)

    # Now look at each bucket, from longest prefix to shortest. Iterate across
    # its sorted networks. If any 2 can be merged, add the new merged network to
    # the next larger bucket and delete the originals.
    #
    # Can you tell why it's OK that this loop terminates at length == 1 instead
    # of 0? Hint: How many x.x.x.x/0 networks can there possibly be?
    for length in range(max(bucket), 0, -1):
        these = bucket[length]
        if len(these) < 2:
            continue

        pairs = pairwise(sorted(these))
        for low, high in pairs:
            if (merged := low.supernet(1)) == high.supernet(1):
                bucket[length - 1].add(merged)
                these.remove(low)
                these.remove(high)
                next(pairs, None)

    # Finally, collect all the resulting networks and return them in sorted
    # order.
    return sorted(set.union(*bucket.values()))


def is_superset(big: list[IPv4Network], little: list[IPv4Network]) -> bool:
    """Return True if every IP address in little is also in big."""
    for little_net in little:
        if not any(big_net.supernet_of(little_net) for big_net in big):
            return False
    return True


def main():
    """Combine a list of IPv4 and/or IPv6 networks into a smaller collection."""
    parser = ArgumentParser(__name__, description=main.__doc__)
    parser.add_argument("network", help="An IPv4 or IPv6 network.", nargs="+")
    args = parser.parse_args()

    ipv4 = []
    ipv6 = []
    for raw in args.network:
        net = ip_network(raw)
        if isinstance(net, IPv4Network):
            ipv4.append(net)
        else:
            ipv6.append(net)

    out = gather(ipv4) + gather(ipv6)
    print("\n".join(str(net) for net in out))
