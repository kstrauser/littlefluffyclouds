"""Unit tests for littlefluffyclouds."""

from littlefluffyclouds import IPv4Network as I
from littlefluffyclouds import dedupe, gather, is_superset


def test_dedupe_simple_dupes():
    """Duplicate networks are removed."""
    net = I("10.0.8.0/24")
    assert dedupe([net, net]) == [net]


def test_dedupe_subernets():
    """Duplicate networks are removed."""
    big = I("10.0.8.0/23")
    little1 = I("10.0.8.0/24")
    little2 = I("10.0.9.0/24")
    assert dedupe(sorted([big, little1, little2])) == [big]


def test_is_superset():
    """Duplicate networks are removed."""
    big = I("10.0.8.0/23")
    little1 = I("10.0.8.0/24")
    little2 = I("10.0.9.0/24")
    assert is_superset([big], [little1, little2])


def test_gather():
    """Merge little networks into bigger once."""
    assert gather(
        [
            I("30.0.33.0/24"),  # Inside the 30. network that comes later
            I("30.0.34.0/24"),  # Inside the 30. network that comes later
            I("10.0.7.0/24"),  # Can't -- alignment issue
            I("10.0.8.0/24"),  # Join vvvv
            I("10.0.9.0/24"),  # Join ^^^^
            I("20.0.14.0/23"),  # Can't -- alignment issue
            I("20.0.16.0/23"),  # Join vvvv
            I("20.0.18.0/23"),  # Join ^^^^
            I("20.0.20.0/23"),  # Can't -- alignment issue
            I("30.0.32.0/20"),  # Doesn't have a neighbor
        ]
    ) == [
        I("10.0.7.0/24"),  # Can't -- alignment issue
        I("10.0.8.0/23"),  # Join vvvv
        I("20.0.14.0/23"),  # Can't -- alignment issue
        I("20.0.16.0/22"),  # Join vvvv
        I("20.0.20.0/23"),  # Can't -- alignment issue
        I("30.0.32.0/20"),  # Doesn't have a neighbor
    ]
