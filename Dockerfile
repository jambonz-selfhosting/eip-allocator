FROM amazon/aws-cli:2.22.35

RUN yum install -y jq && yum clean all
RUN curl -fsSL https://raw.githubusercontent.com/exoscale/cli/master/install-latest.sh | sh
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh
ENTRYPOINT ["/docker-entrypoint.sh"]