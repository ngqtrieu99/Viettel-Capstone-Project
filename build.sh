#!/bin/bash

echo "Building PDCP accelerator"

#BUILD TESTBENCH
# rm -f testcase/output.txt
sudo rm testbench
sudo rm pdcp
sudo rm *.o
sudo killall pdcp

#Compiling
gcc -Iinc/ -c src/testbenchFunc.c -o testbenchFunc.o -fcommon
gcc -Iinc/ -c src/msg_q.c -o msg_q.o -fcommon

#Linking
gcc -Iinc/ msg_q.o testbenchFunc.o src/testbench.c -o testbench -pthread -fcommon

#BUILD PDCP

#compiling
gcc -Iinc/ -c src/snow_3g.c -o snow_3g.o -fcommon
gcc -Iinc/ -c src/zuc.c -o zuc.o -fcommon
gcc -Iinc/ -c src/aes.c -o aes.o -fcommon
gcc -DALLOW_EXPERIMENTAL_API -Iinc/ -c src/pdcpFunc.c -o pdcpFunc.o -lrte_bus_vdev -lrte_eal -lrte_cryptodev -lrte_mbuf -lrte_mempool -mssse3 -fcommon
gcc -Iinc/ -c src/dpdkIntegrity.c -o dpdkIntegrity.o -lrte_eal -lrte_cryptodev -lrte_mbuf -lrte_mempool -mssse3 -fcommon
gcc -Iinc/ -c src/dpdkCiphering.c -o dpdkCiphering.o -lrte_eal -lrte_cryptodev -lrte_mbuf -lrte_mempool -mssse3 -fcommon

#Linking
gcc -DALLOW_EXPERIMENTAL_API -Iinc/ msg_q.o snow_3g.o zuc.o aes.o pdcpFunc.o dpdkIntegrity.o dpdkCiphering.o src/pdcp.c -o pdcp -lrte_eal -lrte_cryptodev -lrte_bus_vdev -lrte_mbuf -lrte_mempool -mssse3 -lpthread -fcommon
