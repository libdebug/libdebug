FROM busybox:latest

RUN printf '\177ELF resolved target\n' > /libdebug-real-sh \
    && rm -f /bin/sh \
    && ln -s /libdebug-real-sh /bin/sh

CMD ["/libdebug-real-sh"]
