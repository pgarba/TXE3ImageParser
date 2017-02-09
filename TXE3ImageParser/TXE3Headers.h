#ifndef TXEHEADERS_H
#define TXEHEADERS_H

/*
	Structs to parse the TXE3 Image
*/


/*
	Set the pragma pack to 1
*/
#pragma pack(1)

/*
	FPT Header
	Name has to be $MN2
*/
const unsigned int TXE_FPT_NAME = 0x54504624;

typedef struct {
	unsigned int Magic; //$FPT
	unsigned int NumEntries;
	unsigned int Version;
	unsigned int Unknown[5];
} TXE_FPT, *PTXE_FPT;

/*
	FPT Partition Header
*/
typedef struct {
	char Name[4];
	char Owner[4];
	unsigned int Offset;
	unsigned int Size;
	unsigned int Unknown[4];	
} TXE_FPTP, *PTXE_FPTP;

enum FPT_partition_type {
	PT_CODE,
	PT_BLOCKIO,
	PT_NVRAM,
	PT_GENERIC,
	PT_EFFS,
	PT_ROM,
};

/*
	Logical Sub-Partition Header
	HeaderMarker has to be '$CPD'
*/
const unsigned int TXE_SPDH_Marker = 0x44504324;
typedef struct {	
	char HeaderMarker[4];
	unsigned int NumberOfEntries;
	unsigned char HeaderVersion;
	unsigned char EntryVersion;
	unsigned char HeaderLength;
	unsigned char Checksum;
	char SubPartitionName[4];
} TXE_SPDH, *PTXE_SPDH;

/*
	Sub-Partition Directory Entry
*/
typedef struct {
	char EntryName[12];
	unsigned int Offset;
	unsigned int Length;
	unsigned int Reseverd;
} TXE_SPDE, *PTXE_SPDE;

/*
	SMIP
*/
typedef struct {	
	unsigned short NumberOfDescriptors;
	unsigned short SizeOfSMIP;	
} TXE_SMIP, *PTXE_SMIP;

/*
	Block Types
*/
enum SMIP_BLOCK_TYPE {
	TXE  = 0,
	PMC  = 1,
	IAFW = 2
};

/*
	SNMIP Block (Descriptors)
*/
typedef struct {
	unsigned short BlockType;
	unsigned short BlockOffset;
	unsigned short BlockLength;
	unsigned short BlockReserved;
} TXE_SMIP_BLOCK, *PTXE_SMIP_BLOCK;


/*
	Sign Manifest Header
	HeaderID has to be '$MN2'
*/
const unsigned int TXE_Manifest_HeaderID = 0x324e4d24;
typedef struct {
	unsigned int HeaderType;
	unsigned int HeaderLength;
	unsigned int HeaderVersion;
	unsigned int Flags;
	unsigned int Vendor;
	unsigned int Date;
	unsigned int Size;
	unsigned int HeaderID;
	unsigned int Reserved;
	unsigned __int64 Version;
	unsigned int SecurityVersionNumber;
	unsigned __int64 Reserved2;
	unsigned __int64 Reserved3[8];
	// Size in DWORDs
	unsigned int ModulusSize;
	// Size in DWORDs
	unsigned int ExponentSize;
	unsigned char PublicKey[256];
	unsigned int Exponent;
	unsigned char Signature[256];
} TXE_MANIFEST, *PTXE_MANIFEST;

/*
	IFWI Authentication header
*/
typedef struct {
	unsigned int AuthHeaderSize;	
	//32-byte IFWI SHA256 hash	
	unsigned char IFWIHash[32];	
	unsigned int Reserved;	
	//256-byte RSA signature for the header
	unsigned char IFWISignature[512]; 
} TXE_IFWI_AUTH, *PTXE_IFWI_AUTH; 

typedef struct _SYS_FW_SFIH {
	//"SFIH"
	unsigned int Signature;
	unsigned int IFWILength;		
	unsigned int IFWIVersion;
	unsigned int BinaryOffset;
	unsigned int BinarySize;
} TXT_SYS_FW_SFIH, *PTXT_SYS_FW_SFIH;




#endif
