FROM amazon/aws-cli:2.22.35

RUN yum install -y jq && \
    yum install -y https://github.com/exoscale/cli/releases/download/v1.93.0/exoscale-cli_1.93.0_linux_amd64.rpm && \
    yum clean all
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh
ENTRYPOINT ["/docker-entrypoint.sh"]