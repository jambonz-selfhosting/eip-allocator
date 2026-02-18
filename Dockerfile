FROM amazon/aws-cli:2.22.35

RUN yum install -y jq && yum clean all
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh
ENTRYPOINT ["/docker-entrypoint.sh"]