FROM wordpress:6.3.1-php8.1-apache

COPY entrypoint.sh /usr/local/bin/proofcms-plugin-entrypoint
RUN chmod 0755 /usr/local/bin/proofcms-plugin-entrypoint

ENTRYPOINT ["proofcms-plugin-entrypoint"]
CMD ["apache2-foreground"]
