FROM ubuntu:18.04

# Install dependecies
RUN apt update
RUN apt install -y build-essential autotools-dev libdumbnet-dev libluajit-5.1-dev libpcap-dev libpcre3-dev zlib1g-dev pkg-config libhwloc-dev cmake
RUN apt install -y liblzma-dev openssl libssl-dev cpputest libsqlite3-dev
RUN apt install -y libtool git autoconf
RUN apt install -y bison flex wget libcurl4-openssl-dev

# Install daq
RUN wget https://www.snort.org/downloads/snortplus/daq-2.2.2.tar.gz
RUN tar -xvzf daq-2.2.2.tar.gz
RUN cd daq-2.2.2 && ./configure && make && make install

# Install flatbuffer
RUN wget -O flatbuffers.tar.gz https://github.com/google/flatbuffers/archive/master.tar.gz
RUN tar -xzvf flatbuffers.tar.gz
RUN cd flatbuffers-master && cmake -G "Unix Makefiles" && make && make install

# Install snort
RUN wget -O snort3.tar.gz https://github.com/snort3/snort3/archive/master.tar.gz
RUN tar -xvzf snort3.tar.gz
RUN ldconfig
RUN cd snort3-master && ./configure_cmake.sh --prefix=/opt/snort && cd build && make -j $(nproc) install
RUN ln -s /opt/snort/bin/snort /usr/sbin/snort

# Install plugin
RUN wget -O snort3_extra.tar.gz https://github.com/snort3/snort3_extra/archive/master.tar.gz
RUN tar -xzvf snort3_extra.tar.gz
ADD extractor snort3_extra-master/src/inspectors/dpx/extractor
ADD CMakeLists.txt dpx.cc packet_generated.h snort3_extra-master/src/inspectors/dpx/
RUN export PKG_CONFIG_PATH=/opt/snort/lib/pkgconfig/ && cd snort3_extra-master && ./configure_cmake.sh --prefix=/opt/snort && cd build && make && make install

# Enable plugin
ADD snort.lua /opt/snort/etc/snort/snort.lua
ENV LUA_PATH /opt/snort/include/snort/lua/\?.lua\;\;
ENV SNORT_LUA_PATH /opt/snort/etc/snort

ENTRYPOINT [ "snort", "-c", "/opt/snort/etc/snort/snort.lua", "--plugin-path", "/opt/snort/lib/snort_extra/", "-i", "eth0" ]