# Little Fluffy Clouds: Gather a bunch of small adjacent networks into larger ones.

Sometimes you find yourself staring at a bunch of networks that look like that could be compressed if you could just kind of smoosh them together enough.

`littlefluffyclouds` is that smoosher.

For example, this AS has a huge number of small networks. In many cases, two /24 networks are adjacent and could be combined into a single /23. There's also a big /14 network with 252 smaller networks inside it. If you use that raw output in a command or a firewall rule, etc., then you'd have to add _7,945_ networks. Wow! That's too many.

```shell
$ curl -s https://ip.guide/AS9121 | jq -r .routes.v4[]
2.17.224.0/22
2.17.228.0/22
2.17.232.0/22
2.17.236.0/22
2.20.24.0/22
23.55.52.0/22
[7,933 similar lines]
212.175.175.0/24
212.175.246.0/24
212.175.250.0/24
212.175.251.0/24
212.175.252.0/24
212.175.255.0/24
```

Instead, let's let `littlefluffyclouds` mash all those little clouds into a smaller number of big ones that cover the exact same collection of addresses:

```shell
$ uv run littlefluffyclouds $(curl -s https://ip.guide/AS9121 | jq -r .routes.v4[])
2.17.224.0/20
2.20.24.0/22
23.55.52.0/22
62.248.0.0/17
78.160.0.0/11
81.212.0.0/14
85.96.0.0/12
88.224.0.0/11
93.155.104.0/22
95.0.0.0/12
176.52.176.0/22
193.110.209.0/24
194.54.32.0/19
195.174.0.0/15
212.156.0.0/16
212.174.0.0/15
```

The end result is 16 networks. _Sixteen._ That's just about 1/500th the original size _with identical address space coverage._ Yay, big clouds!

## API

"But I don't _want_ to use a command line," you might say. Neither did I! `littlefluffyclouds` makes that easy peasy lemon squeezy!

```python
from ipaddress import IPv4Network as I
print(gather([I('10.0.8.0/24'), I('10.0.9.0/24'), I('10.0.10.0/24'), I('10.0.11.0/24')]))
```

That prints `[IPv4Network('10.0.8.0/22')]`. Whoa! I know, right?

## But... why?

Some differences with other packages which do the same thing:

- It's often way faster. Like ridiculously faster. Think milliseconds versus minutes faster.
- It's written with modern Python with typing and all that.
- Its command line is _optional_. All the work is done in a handy API that you can call from your own project.
- It gives correct results, even in pathological cases where little networks are intermingled with bigger ones. That case causes several other packages to only merge the big networks or the little ones, even when you could a bunch of little ones with one big one.

## Version history

**v0.1.0, 2025-09-17:** Initial release.
