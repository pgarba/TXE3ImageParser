#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vector>
#include <tuple>


#include "TXE3Headers.h"

int unhuff(unsigned char *huff, unsigned char *out, int outlen, int flags, int version);

/*
	Small helper to get the file size
*/
size_t GetFileSize(FILE *fp) {
	size_t size;
	fseek(fp, 0, SEEK_END);
	size = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	return size;
}


// Write data to filename
void WriteFile(char *FileName, unsigned char *Data, int Size) {
	char OFileName[9] = "";
	memcpy(OFileName, FileName, 8);
	OFileName[8] = '\0';

	FILE *fOut = fopen(OFileName, "wb");
	if (!fOut) {
		printf("[*] Could not open %s for writing!\n\n", OFileName);
	}
	fwrite(Data, Size, 1, fOut);
	fclose(fOut);

	printf("[*] File %s dumped!\n", OFileName);
}

/*
	Print arrays
*/
void PrintArray(const unsigned char *Array, int Size) {
	for (int i = 0; i < Size; i++) {
		if (i && !(i % 16)) {
			printf("\n\t\t\t\t");
		}
		printf("%02X", Array[i]);
	}
	printf("\n");
}

/*
	Parse the Sub Partition
*/
void Parse_TXE_SPDH(unsigned char *TXEImage,  PTXE_SPDH PSPDH) {
	if (*(unsigned int *)&PSPDH->HeaderMarker != TXE_SPDH_Marker) {
		printf("[*] Invalid Logical Sub-Partition Header !\n\n");
		return;
	}

	// Print Logical Sub-Partition Header
	printf("[*] Logical Sub-Partition Header\n");
	printf("[-] HeaderMarker:\t'%.*s'\n", (int) sizeof(PSPDH->HeaderMarker), PSPDH->HeaderMarker);
	printf("[-] NumberOfEntries:\t%i\n", PSPDH->NumberOfEntries);
	printf("[-] HeaderVersion:\t%i\n", PSPDH->HeaderVersion);
	printf("[-] EntryVersion:\t%i\n", PSPDH->EntryVersion);
	printf("[-] HeaderLength:\t0x%X\n", PSPDH->HeaderLength);
	printf("[-] Checksum:\t\t0x%X\n", PSPDH->Checksum);
	printf("[-] SubPartitionName:\t'%.*s'\n", (int) sizeof(PSPDH->SubPartitionName), PSPDH->SubPartitionName);
	printf("\n");

	// Manifest list
	typedef std::pair<char *, PTXE_MANIFEST> TManPair;
	std::vector<TManPair> VecManifest;

	//Parse Sub-Partition Directory Entry
	PTXE_SPDE PSDPE = (PTXE_SPDE)(PSPDH + 1);

	printf("[*] Logical Sub-Partition Header - Count %i\n", PSPDH->NumberOfEntries);
	for (unsigned int i = 0; i < PSPDH->NumberOfEntries; i++) {
		printf("[-] EntryName:\t\t'%.*s'\n", (int) sizeof(PSDPE->EntryName), PSDPE->EntryName);
		printf("[-] Offset:\t\t0x%X\n", PSDPE->Offset);
		printf("[-] Length:\t\t0x%X\n", PSDPE->Length);
		printf("[-] Reseverd:\t\t0x%X\n", PSDPE->Reseverd);

		//Check if manifest
		if (strstr(PSDPE->EntryName, ".man") || strstr(PSDPE->EntryName, ".key")) {
			VecManifest.push_back(TManPair((char *) PSDPE->EntryName,(PTXE_MANIFEST)(TXEImage + PSDPE->Offset)));
		}

		//Dump file
		WriteFile(PSDPE->EntryName, TXEImage + PSDPE->Offset, PSDPE->Length);

		printf("\n");

		//Next Entry
		++PSDPE;
	}
	printf("\n");

	// Parse the manifests
	for (auto TManifest : VecManifest) {
		PTXE_MANIFEST PManifest = TManifest.second;
		if (PManifest->HeaderID != TXE_Manifest_HeaderID) {
			printf("[*] Invalid Manifest Header !\n\n");
			return;
		}		

		// Print Manifest header
		printf("[*] Manifest Header: '%.*s'\n", sizeof(TManifest.first), TManifest.first);
		printf("[-] HeaderType:\t\t\t0x%X\n", PManifest->HeaderType);
		printf("[-] HeaderLength:\t\t0x%X\n", PManifest->HeaderLength);
		printf("[-] HeaderVersion:\t\t0x%X\n", PManifest->HeaderVersion);
		printf("[-] Flags:\t\t\t0x%X\n", PManifest->Flags);
		printf("[-] Vendor:\t\t\t0x%X\n", PManifest->Vendor);
		printf("[-] Date:\t\t\t0x%X\n", PManifest->Date);
		printf("[-] Size:\t\t\t0x%X\n", PManifest->Size);
		printf("[-] HeaderID:\t\t\t'%.*s'\n", (int) sizeof(PManifest->HeaderID), (char *)&PManifest->HeaderID);
		printf("[-] Reserved:\t\t\t0x%X\n", PManifest->Reserved);
		printf("[-] Version:\t\t\t0x%I64X\n", PManifest->Version);
		printf("[-] SecurityVersionNumber:\t0x%X\n", PManifest->SecurityVersionNumber);
		printf("[-] Reserved:\t\t\t0x%I64X\n", PManifest->Reserved2);
		printf("[-] Reserved:\t\t\t0x");
		for (int i = 0; i < 8; i++) {
			printf("%I64X", PManifest->Reserved3[i]);
		}
		printf("\n");
		printf("[-] ModulusSize:\t\t%i\n", PManifest->ModulusSize);
		printf("[-] ExponentSize:\t\t%i\n", PManifest->ExponentSize);
		printf("[-] PublicKey:\t\t\t");
		PrintArray(PManifest->PublicKey, sizeof(PManifest->PublicKey));
		printf("[-] Exponent:\t\t\t%i\n", PManifest->Exponent);
		printf("[-] Signature:\t\t\t");
		PrintArray(PManifest->Signature, sizeof(PManifest->Signature));
	}
}

int main(int argc, char **argv) {
	printf("Intel TXE3 Image Parser (c) pg\n\n");

	// Check arguments
	if (argc < 2) {
		printf("[*] Usage: %s TXEImage.bin\n\n", argv[0]);
		return 1;
	}

	// Open file
	FILE *fTXEImage = fopen(argv[1], "rb");
	if (!fTXEImage) {
		printf("[*] Could not open %s!\n\n", argv[1]);
		return 1;
	}

	// Read the content into memory	
	size_t TXEImageSize = GetFileSize(fTXEImage);
	unsigned char * TXEImage = (unsigned char *) calloc(1, TXEImageSize);
	fread(TXEImage, TXEImageSize, 1, fTXEImage);
	fclose(fTXEImage);

	// Parse the Flash partition table
	PTXE_FPT FPT = (PTXE_FPT) (TXEImage + 0x10);
	// Check FPT Magic
	if (FPT->Magic != TXE_FPT_NAME) {
		printf("[*] Invalid FPT Header !\n\n");
		return 1;
	}

	// Print FPT Header
	printf("[*] FPT Header\n");
	printf("[-] Magic:\t\t'%.*s'\n", (int) sizeof(FPT->Magic), (char *) &FPT->Magic);
	printf("[-] NumEntries:\t\t%i\n", FPT->NumEntries);
	printf("[-] Version:\t\t0x%08X\n", FPT->Version);


	// Parse the FPT Partitions
	PTXE_FPTP FPTP = (PTXE_FPTP) (FPT + 1);
	for (int i = 0; i < (int) FPT->NumEntries; i++) {
		printf("[*] FPT Parition\n");
		printf("[*] Name:\t\t%.*s\n", (int) sizeof(FPTP->Name), FPTP->Name);
		printf("[*] Owner:\t\t%.*s\n", (int) sizeof(FPTP->Owner), FPTP->Owner);
		printf("[*] Offset:\t\t0x%08X\n", FPTP->Offset);
		printf("[*] Size:\t\t0x%08X\n", FPTP->Size);

		// Parse partition
		if (FPTP->Size) {
			Parse_TXE_SPDH(&TXEImage[FPTP->Offset], (PTXE_SPDH)&TXEImage[FPTP->Offset]);
		}	

		// Next partition
		FPTP++;
	}

	return 0;
}