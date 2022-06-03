# Cidr-Autosolve

Cidr-Autosolve is a Python script that takes a big IP range and numerous small IP range exclusions and outputs all IPs in the large range except those in the small range exclusion in Cidr notation.

An example would be:
```
python3 cidr-autosolve.py 10.15.0.0/17 "10.15.15.0/24, 10.15.32.0/24, 10.20.55.0/24 10.20.90.0/24"
```
![Example](/assets/images/example.png)

## Where is this useful?

This is useful during an assessment where scanning of a large IP range is required and there are certain small IP range exclusions such as:
```
IP Range: 10.5.0.0/16
Excluded: 10.5.15.0/24, 10.5.22.0.24, 10.5. 61.0/24
```
