# I. Uasge

```
usage: sqlicheck.py [-h] [-url URL] [-packet PACKET] [-payloadlist PAYLOADLIST] [-log] [-cookies]

options:
  -h, --help            show this help message and exit
  -url URL              Target URL (e.g. "http://www.site.com/vuln.php?id=1")
  -packet PACKET        Load HTTP request from a file path (e.g. "./package.txt")
  -payloadlist PAYLOADLIST
                        Load list payloads from a file path (e.g. "./payloads.txt")
  -log                  Show the log
  -cookies              Cookies testing
```

# II. Example

Scan URL

```
python3 sqlicheck.py -url "https://0a4200ee044a2a22815b2aa100fd008d.web-security-academy.net/filter?category=Pets"
```

Scan POST request with package:

```
python3 sqlicheck.py -packet "./package.txt"
```

Scan GET request - cookies with package:

```
python3 sqlicheck.py -packet "./package.txt" -cookies
```

