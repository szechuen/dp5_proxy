while read host config; do
  fab -H $host run_server:$config &
done < servers
