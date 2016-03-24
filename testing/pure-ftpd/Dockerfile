FROM stilliard/pure-ftpd

RUN mkdir /home/ftp \
 && dd if=/dev/urandom of=/home/ftp/data.dat bs=1M count=16 \
 && useradd \
        -d /home/ftp \
        -s /bin/false \
    ftp

# Same as upstream's CMD, but with -E removed to allow anonymous ftp
CMD /usr/sbin/pure-ftpd -c 50 -C 10 -l puredb:/etc/pure-ftpd/pureftpd.pdb -j -R -P $PUBLICHOST -p 30000:30009
