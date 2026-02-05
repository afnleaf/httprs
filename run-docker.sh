#!/bin/bash

docker run -it --rm \
  --name sniffer \
  --cap-add=NET_RAW \
  --cap-add=NET_ADMIN \
  --sysctl net.ipv6.conf.all.disable_ipv6=1 \
  -v "$(pwd)":/app \
  -v cargo-cache:/app/target \
  -w /app \
  rust:latest \
  bash -c "
    trap 'kill %1 2>/dev/null; exit' INT TERM
    apt-get update && apt-get install -y iputils-ping > /dev/null 2>&1
    cargo build --release 2>&1
    ./target/release/raw_socket &
    sleep 1
    echo '--- Pinging 8.8.8.8 ---'
    ping -4 -c 5 8.8.8.8
    echo '--- Done ---'
    kill %1 2>/dev/null
  "

#docker run -it --rm \
#  --name sniffer \
#  --cap-add=NET_RAW \
#  --cap-add=NET_ADMIN \
#  --sysctl net.ipv6.conf.all.disable_ipv6=1 \
#  -v "$(pwd)":/app \
#  -v cargo-cache:/app/target \
#  -w /app \
#  rust:latest \
#  bash

#docker run -it --rm \
#  --cap-add=NET_RAW \
#  --cap-add=NET_ADMIN \
#  --sysctl net.ipv6.conf.all.disable_ipv6=1 \
#  -v "$(pwd)":/app \
#  -v cargo-cache:/app/target \
#  -w /app \
#  rust:latest \
#  #bash -c "cargo build && (cargo run &) && sleep 2 && ping -4 8.8.8.8"
#  bash -c "apt-get update && apt-get install -y iputils-ping && cargo build && (cargo run &) && sleep 2 && ping -4 8.8.8.8"
#

#docker run -it --rm \
#  --net=host \
#  --cap-add=NET_RAW \
#  --cap-add=NET_ADMIN \
#  -v "$(pwd)":/app \
#  -w /app \
#  rust:latest \
#  bash
#  
#
#  #-v cargo-cache:/app/target \
