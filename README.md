# hashcracker

  before compiling:
need OpenSSL and OpenMPI. To install on debian buster: 
sudo apt-get install libssl-dev openmpi-bin openmpi-common libopenmpi-dev libopenmpi3 openmpi-doc

  compile:
mpicc hashcracker.c -lssl -lcrypto -lm -lcrypt -o hashcracker
 
  run:
Usage: hashcracker [options] hash...  
Options:  
--hash-function      MD5, SHA-512, or linux shadow password  
--salt               string to use as a salt  
--min                minimum characters for test strings  
--max                maximum characters for test strings  
--ascii-start        ascii character to begin checking with  
--ascii-end          ascii character to end checking with  

example: mpirun -np 2 hashcracker --hash-function MD5 97d986e2afa2c72986972e6433fbeaf9
