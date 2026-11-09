FROM wordpress:6.3.1-php8.1-apache@sha256:071c1f5bd378578393716294a81c07ca90e71382f8c464fa8a48a58bac0a53dc

COPY entrypoint.sh /usr/local/bin/proofcms-plugin-entrypoint
RUN chmod 0755 /usr/local/bin/proofcms-plugin-entrypoint

ENTRYPOINT ["proofcms-plugin-entrypoint"]
CMD ["apache2-foreground"]
