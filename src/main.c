#include "../include/ip_v4.h"
#include "../include/ethernet_II.h"

int main () { // test
	int fileDesc = attachToInterface("en1");

	char *ipPayload = "Hello, Internet";
	u_int payloadLength = 15;

	byte* ipDatagram = buildIPv4Datagram(ipPayload, payloadLength);
	
	EthernetBlueprint eth;
	eth.fileDesc = fileDesc;

	eth.destinationMacAddress[0] = 0x3456;
	eth.destinationMacAddress[1] = 0x3456;
	eth.destinationMacAddress[2] = 0x3456;

	eth.sourceMacAddress[0] = 0x9876;
	eth.sourceMacAddress[1] = 0x9876;
	eth.sourceMacAddress[2] = 0x9876;

	eth.etherType = 0x0008;
	eth.message = ipDatagram;
	eth.messageLength = 20 + 15;
	int res = writeEthernetFrame(eth);
}
