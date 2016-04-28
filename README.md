# ipfix_collector

Initial import of multithreading replacement for Silk flowcap utilising libfixbuf

Code very beta.  DO NOT USE IN PRODUCTION

Usage:
  collect [OPTION...] IPFIX Collector

Help Options:
  -h, --help          Show help options

Application Options:
  -d, --directory     Output Directory
  -p, --port          Port to receive IPFIX on
  -r, --rotate        Rotate file every N seconds
  -t, --threads       Number of threads for UDP listener
