FROM ubuntu:xenial

RUN apt-get update
ADD dp5 /dp5

RUN apt-get install -y libgmp3-dev libntl-dev libssl-dev python-dev build-essential cmake
RUN cd dp5 && mkdir build && cd build && cmake .. && make

RUN apt-get install -y python-cherrypy python-requests python-cffi python-twisted
RUN cd dp5 && cd build && python setup.py install

CMD bash
