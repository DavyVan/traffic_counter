# traffic_counter
This's originally a sub-project of xWeaver.

# How to develop upon
## Get ready to compile libpcap
* bison


    apt-get install bison

* g++
* flex

## Compile libpcap
    wget http://www.tcpdump.org/release/libpcap-1.8.1.tar.gz
    tar -zvxf libpcap-1.8.1.tar.gz
    cd libpcap-1.8.1/
    ./configure
    make
    sudo make install

## Compile Traffic Counter
It's quite simple.

    make
