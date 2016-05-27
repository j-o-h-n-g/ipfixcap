# ipfixcap

Initial import of multithreading replacement for Silk flowcap utilising libfixbuf

Code still quite beta.  Attempts to mimic flowcap.  Configuration very similar
with two extra options (port and threads).  One day these will be determined
automatically.   Some flowcap options are ignored entirely, in particular any 
logging configuration.  All logging is currently via systemd.

~~~
Usage:
  ipfixcap [OPTION...] IPFIX Collector

Help Options:
  -h, --help                      Show help options

Application Options:
  -d, --destination-directory     Output Directory
  -p, --port                      Port to receive IPFIX on
  --timeout                       Rotate file every N seconds
  --max-file-size                 Maximum Filesize
  -t, --threads                   Number of threads for UDP listener
  -s, --sensor-configuration      Sensor Configuration File
  --pidfile                       Location of pidfile
  --no-daemon                     Do not fork off as a daemon (for debugging)
  --compression-method            Compression Method [none,zlib,lzo1x,best]

~~~
