Elisaviihde
=====

**Elisa Viihde Python library with usage examples**

License: GPLv3 http://www.gnu.org/copyleft/gpl.html

Requires: http://docs.python-requests.org/

Developed with: Python 2.7.6

[![Build Status](https://travis-ci.org/enyone/elisaviihde.svg?branch=master)](https://travis-ci.org/enyone/elisaviihde)

**Release 1.0**

[Download .zip](https://github.com/enyone/elisaviihde/archive/1.0.zip)
or [Download .tar.gz](https://github.com/enyone/elisaviihde/archive/1.0.tar.gz)

Simple example
-----
```
$ cp examples/example.py .
$ python example.py -u username -p password
```
Output:
```
Found folders:
3603265: Ajankohtainen kakkonen
2540806: Dokumentit
2540838: Elokuvat

Found recordings from folder 3603265:
1812084: Ajankohtainen kakkonen (ke 25.02.2015 13.25)
1811241: Ajankohtainen kakkonen (ti 24.02.2015 21.00)
1797570: Ajankohtainen kakkonen (ke 18.02.2015 14.45)

Found stream uri from recording 1812084:
http://netpvrpa.cdn.elisaviihde.fi/stream.php?id=1812084&...
```

VLC playlist example
-----
```
$ cp examples/example_vlc.py .
$ python example_vlc.py -u username -p password -f myplaylist.xspf
```

Creates XSPF playlist file (XML Shareable Playlist Format) containing all recordings from all folders recursively.

http://en.wikipedia.org/wiki/XML_Shareable_Playlist_Format

![Build Status](https://raw.githubusercontent.com/enyone/elisaviihde/master/examples/example_playlist.png)
