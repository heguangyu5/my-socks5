# socks5 proxy

    ./my-socks5 -h
    usage: ./my-socks5 -u username -p password [-P port] [-F] [-h]
           -u  username, required
           -p  password, required
           -P  default 5555
           -F  run in foreground
           -h  usage info

- currently only support TCP
- currently only support Username/Password AUTH
- currently it is Half Duplex

# Build Firefox from source to support SOCKS5 Username/Password Authentication

- Chrome dose not support SOCKS5 authentication, @see https://bugs.chromium.org/p/chromium/issues/detail?id=256785
- Firefox dose support SOCKS5 authentication, but NO userinterface available, that's why we need BUILD FROM SOURCE.
- @see https://developer.mozilla.org/en-US/docs/Mozilla/Developer_guide/Build_Instructions/Simple_Firefox_build/Linux_and_MacOS_build_preparation

        sudo apt-get install autoconf2.13
    
        # Ubuntu 12.04
        # firefox need gcc-4.8
        sudo apt-get build-dep firefox
        cd /usr/bin/
        sudo rm g++ gcc
        sudo ln -s /usr/lib/gcc-mozilla/bin/gcc .
        sudo ln -s /usr/lib/gcc-mozilla/bin/g++ .

        apt-get source firefox
        cd firefox-50.1.0+build2
        ./mach bootstrap
        # Firefox for Desktop
    
        # edit toolkit/mozapps/update/tests/moz.build
        # remove 'data/complete.exe', 'data/partial.exe'
    
        ./mach build
        # it will take a long while
    
        # edit netwerk/socket/nsSOCKSIOLayer.cpp
        # line 281
        -
        mProxy->GetUsername(mProxyUsername);
        +
        char *my_socks5_username = getenv("MY_SOCKS5_USERNAME");
        if (my_socks5_username != NULL) {
            mProxyUsername = my_socks5_username;
        } else {
            mProxy->GetUsername(mProxyUsername);
        }
        # line 712
        -
        nsCString password;
        mProxy->GetPassword(password);
        +
        char *my_socks5_password = getenv("MY_SOCKS5_PASSWORD");
        if (my_socks5_password == NULL) {
            return PR_FAILURE;
        }
        nsCString password;
        password = my_socks5_password;
    
        ./mach build
        ./mach package
    
        cd obj-x86_64-pc-linux-gnu/dist/
        cp firefox-50.1.0.en-US.linux-x86_64.tar.bz2 ~/Downloads/

# Run firefox

    # select "Proxy DNS when using SOCKS v5"
    # ssh -L 127.0.0.1:5555:127.0.0.1:5555 user@remote
    env MY_SOCKS5_USERNAME=user MY_SOCKS5_PASSWORD=pass /home/heguangyu5/firefox/firefox
