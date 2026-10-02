#!/bin/sh
set -eu

for slug in contact-form-7 litespeed-cache ultimate-member; do
    test -d "/fixtures/${slug}"
    rm -rf "/usr/src/wordpress/wp-content/plugins/${slug}"
    cp -a "/fixtures/${slug}" "/usr/src/wordpress/wp-content/plugins/${slug}"
done

exec docker-entrypoint.sh "$@"
