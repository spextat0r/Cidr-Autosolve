# Cidr-Autosolve

Cidr-Autosolve is a python script that will take a large IP range and multiple small IP range exclusions and output in Cidr notation all IPs in the large range excluding the small range exclusion.

An example would be:
```
python3 cidr-autosolve.py 10.15.0.0/17 "10.15.15.0/24, 10.15.32.0/24, 10.20.55.0/24 10.20.90.0/24"
```
![Example](/assets/images/example.png)
