#!/bin/bash

## Stat monitoring

# Quck real-time example with verbose
#./rtpac -ul -n3 -b1000 -w1000 -v

## Real-Time Anomaly detection

# Quick real-time example with graph
./rtpac -c0.3 -ul -n3 -mi -b1000 -w500 -g

# Realistic real-time example with graph
#./rtpac -ul -n3 -mi -b1000 -w1000 -g

## Historical Anomaly Detection

## 2/7 with 0.01% false
#./rtpac -c10 -mi -ln -ul -upc -b10000000 -w1000 -t./testdata/training -a./testdata/attack

#./rtpac -ln -ul -upc -b10000000 -w1000 -t./testdata/training -a./testdata/attack
#./rtpac -ln -ul -b10000000 -w500 -t./testdata/training -a./testdata/attack

