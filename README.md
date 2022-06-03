# Cidr-Autosolve

Cidr-Autosolve is a Python script that takes a big IP range and numerous small IP range exclusions and outputs all IPs in the large range except those in the small range exclusion in Cidr notation.

An example would be:
```
python3 cidr-autosolve.py 10.15.0.0/17 "10.15.15.0/24, 10.15.32.0/24, 10.20.55.0/24 10.20.90.0/24"
```
![Example](/assets/images/example.png)
