#include <stdlib.h>
#include <stdio.h>
#include <net/bpf.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>

typedef u_char byte;
typedef u_short double_byte;

typedef struct EthernetBlueprint {
	int fileDesc;
	double_byte destinationMacAddress;
	double_byte sourceMacAddress;
	double_byte etherType;
	char* message;
	u_int messageLength;
} EthernetBlueprint;

// Takes interface name provided and configures a BPF to attach to it
// then returns the BPF fileDescriptor to read/write
int attachToInterface(char* interfaceName) {
	char filePath[10];
	int fileDesc;
	for (int i = 0; i < 100; i++) {
		sprintf(filePath, "/dev/bpf%i", i);
		fileDesc = open(filePath, O_RDWR);
		if (fileDesc >= 0) {
			break;
		}
		if (errno != EBUSY) {
			printf("Unexpected error code on opening BPF %s", strerror(errno));
			return -1;
		}

		if (i == 99) {
			printf("Could not find available BPF");
			return -1;
		}
	}

	printf("Found available file: %s \n", filePath);

	printf("Attaching to interface: %s \n", interfaceName);

	struct ifreq interface;
	strcpy(interface.ifr_name, interfaceName);

	int err = ioctl(fileDesc, BIOCSETIF, &interface);
	if (err == -1) {
		printf("Error attaching interface: %i\n", err);
		return -1;
	}

	u_int maxBufferLength;
	err = ioctl(fileDesc, BIOCGBLEN, &maxBufferLength);
	if (err == -1) {
		printf("Error reading buffer length. %s\n", strerror(errno));
		return -1;
	}

	printf("Buffer length of %u \n", maxBufferLength);

	printf("Reading the data layer type of the interface...");
	u_int dataLinkType;
	err = ioctl(fileDesc, BIOCGDLT, &dataLinkType);
	if (err == -1) {
		printf("Data link type unavailable. %s\n", strerror(errno));
		return -1;
	}
	printf("Data link type: %u \n", dataLinkType);

	printf("Flushing bpf... \n");
	err = ioctl(fileDesc, BIOCFLUSH);
	if (err == -1) {
		printf("Flush failed. %s\n", strerror(errno));
		return -1;
	}

	// we will be defining all headers ourself
	u_int turnOffHeaderAutocomplete = 1;
	err = ioctl(fileDesc, BIOCSHDRCMPLT, &turnOffHeaderAutocomplete);
	if (err == -1) {
		printf("Unable to turn off header completion. %s\n", strerror(errno));
		return -1;
	}

	u_int captureIncomingPacketsOnly = 0;
	err = ioctl(fileDesc, BIOCSSEESENT, &captureIncomingPacketsOnly);
	if (err == -1) {
		printf("Unable to turn off outbound packet capture. %s\n", strerror(errno));
		return -1;
	}

	return fileDesc;
}

// write ethernet frame to fileDescriptor provided
int writeEthernetFrame(EthernetBlueprint frame) {
	printf("Writing to BPF...");

	u_int messageSize = sizeof(frame.message[0]) * frame.messageLength;
	u_int headerSize = 12; // 12 bytes == length of source + dest header
	u_int bufferSize = headerSize + messageSize;
	byte* buffer = malloc(bufferSize);

	memcpy(buffer, frame.destinationMacAddress, 6);
	memcpy(buffer + 6, frame.sourceMacAddress, 6);
	memcpy(buffer + 12, frame.message, frame.messageLength);

	int res = write(frame.fileDesc, buffer, bufferSize);
	if (res == -1) {
		printf("Didnt work. %s\n", strerror(errno));
		return -1;
	}

	printf("Sent %i bytes \n", res);
	return res;
}

void readFrame(int fileDesc) {
	// TODO
}


/*
Reference:

Man pages:
http://www.manpagez.com/man/4/bpf/osx-10.6.php
http://www.manpagez.com/man/2/ioctl/

Data link types as found in net/bpf
	DLT_NULL	0
	DLT_EN10MB	1
	DLT_EN3MB	2
	DLT_AX25	3
	DLT_PRONET	4
	DLT_CHAOS	5
	DLT_IEEE802	6
	DLT_ARCNET	7
	DLT_SLIP	8
	DLT_PPP		9
	DLT_FDDI	10
	DLT_ATM_RFC1483	11
	DLT_RAW		12
**/