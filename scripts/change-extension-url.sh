#!/bin/bash

: ${1?' You forgot to supply an url the API is running on'}

echo $1

search_string="http://localhost:8000"

for d in apps/mainsite/static/extensions/*/context.json ; do
    echo "editing $d"
    sed -i '' "s#$search_string#$1#g" "$d"
done
