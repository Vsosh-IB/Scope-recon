FROM ubuntu:latest
LABEL authors="xsafter"

RUN apt-get update && apt-get upgrade -y
RUN apt-get install -y git wget build-essential python3 python3-pip openssl git make unzip whois prips curl

RUN wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz; tar -xvf go1.21.0.linux-amd64.tar.gz; mv go /usr/local

ENV GOROOT=/usr/local/go
ENV GOPATH=$HOME/go
ENV PATH=$GOPATH/bin:$GOROOT/bin:$PATH

RUN go install github.com/hakluke/hakrevdns@latest
RUN go install github.com/d3mondev/puredns/v2@latest
RUN git clone https://github.com/blechschmidt/massdns
RUN cd massdns && make && cp bin/massdns /usr/bin/massdns
RUN go install -v github.com/projectdiscovery/uncover/cmd/uncover@latest

ENV PIP_BREAK_SYSTEM_PACKAGES 1
RUN apt-get install pipx -y
RUN pipx ensurepath
RUN pipx install bbot
RUN pip3 install python-whois bbot>=2.0.1 --break-system-packages
RUN pip3 install pyOpenSSL~=24.0.0 baddns~=1.1.815 ipwhois fofa-py --break-system-packages

RUN wget https://updates-static.shodan.io/tools/favscan/favscan-linux-x86_64
RUN mv ./favscan-linux-x86_64 /bin
RUN chmod +x /bin/favscan-linux-x86_64

COPY . /root
RUN mkdir -p /root/.config/bbot/
ADD ./bbot_templates/bbot.yml /root/.config/bbot/bbot.yml

WORKDIR /root

ENTRYPOINT ["python3", "src/main.py"]
CMD ["-h"]
