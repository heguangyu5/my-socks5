# socks5 proxy

    ./my-socks5 -h
    usage: ./my-socks5 -u username -p password [-P port] [-F] [-h]
           -u  username, required
           -p  password, required
           -P  port, default 1080, should > 1024
           -F  run in foreground
           -h  usage info

- currently only support TCP
- currently only support Username/Password AUTH
- currently only support IPV4
- currently it is Half Duplex
