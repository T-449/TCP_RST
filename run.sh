g++ packetSender.cpp -o sender
g++ packetSniffer.cpp -o sniffer -lpcap
sudo chown root:root ./sniffer
sudo chmod a+s ./sniffer
./sniffer
