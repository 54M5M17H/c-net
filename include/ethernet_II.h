#include <stdlib.h>
#include <stdio.h>
#include <net/bpf.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/time.h>
#include <unistd.h>

#include "general.h"

typedef struct EthernetBlueprint {
	int fileDesc;
	double_byte destinationMacAddress[3];
	double_byte sourceMacAddress[3];
	double_byte etherType;
	byte* message;
	u_int messageLength;
} EthernetBlueprint;

int attachToInterface(char* interfaceName);
void readFrame(int fileDesc);
void printMacAddr(double_byte macAddr[6]);
int writeEthernetFrame(EthernetBlueprint frame);
