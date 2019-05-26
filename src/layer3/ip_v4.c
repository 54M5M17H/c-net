#include "../../include/ip_v4.h"

// 0b: means a binary literal

// Returns pointer to IPv4 datagram
byte* buildIPv4Datagram(char *payload, u_int payloadLength) {
	byte assumedHeaderLengthInBytes = 20;
	byte *datagram = malloc(assumedHeaderLengthInBytes * sizeof(byte));

	// version (4 bits) = 0100 === 4
	byte version = 0b100 << 4; // to give us the front half of the byte

	// header length, in terms of 32 bit words (4 bytes)
	// e.g. 64 bit header would have header length set to 2
	// 20 bytes -> 5 words -> 0101
	byte assumedHeaderLengthInWords = assumedHeaderLengthInBytes / 4;

	datagram[0] = version + assumedHeaderLengthInWords;

	// precedence of service -- hardcode to low
	datagram[1] = 0;

	// total datagram length in bytes (2 bytes)

	byte totalDatagramLength = payloadLength + assumedHeaderLengthInBytes;
	datagram[2] = 0; // dont need first byte for length < 256
	datagram[3] = totalDatagramLength;

	// unique id (2 bytes)
	datagram[4] = 0b11111111;
	datagram[5] = 0b11111111; // hardcode to this for now

	/** flags (3 bits)
	 * 		1) unused -- set 0
	 * 		2) (DF) 0 = May Fragment,  1 = Don't Fragment.
	 * 		3) (MF) 0 = Last Fragment, 1 = More Fragments.
	 * we'll hardcode for now
	*/
	byte flags = 0b110;

	// fragment offset (13 bits) -- offset from previous fragments in datagram
	byte offset = 0;

	datagram[6] = (flags << 5); // + offset;
	datagram[7] = 0;

	// TTL (byte) -- hops allowed
	datagram[8] = 2;

	// protocol(1 byte)
	datagram[9] = 0x07;

	// header checksum (2 bytes) -- checksum of 16 bit words
	// TODO: which parts?!
	// datagram[10]
	// datagram[11]

	// source address (4 bytes) -- some nonsense
	datagram[12] = 192;
	datagram[13] = 168;
	datagram[14] = 0;
	datagram[15] = 2;

	// destination address (4 bytes) -- harcode to router
	// 192.168.0.1
	datagram[16] = 192;
	datagram[17] = 168;
	datagram[18] = 0;
	datagram[19] = 1;

	memcpy(&datagram[20], &payload, payloadLength);
	
	printf("Returning IP datagram... \n");
	return &datagram[0];
}


/** 
 * Reference:
 * 
 * IPv4 RFC:
 * https://tools.ietf.org/html/rfc791
 * 
 * 
 * 
 * Datagram Headers:
 * 0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version|  IHL  |Type of Service|          Total Length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Identification        |Flags|      Fragment Offset    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Time to Live |    Protocol   |         Header Checksum       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source Address                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Destination Address                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 
*/