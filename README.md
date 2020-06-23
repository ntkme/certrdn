# certrdn

Get X.509 certificate's RDN (relative distinguished name) value by OID.

### Installation

``` sh
autoreconf -fiv && ./configure && make && make install
```

### Usage

```
Usage: certrdn oid [pem...]
```

```
$ certrdn 2.5.4.3 cert.pem
example.com
```
