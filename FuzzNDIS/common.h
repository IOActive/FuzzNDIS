#pragma once
#include "stdafx.h"
#include <windows.h>
#include "DeltaFuzz.h"

#include <iphlpapi.h>
#include <ntddndis.h>

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x)) 
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))


#define FUZZ_UNIT_MEM_SIZE 0x500000
FUZZER_OBJECT *g_fuzzer;
UINT32 g_seed;
UINT32 tsc_aux1;

/* FuzzNDIS */
BOOL GetInformationFromAdapters(WCHAR *matchDesc, char *pOutAdapterStr);
DWORD getSupportedList(HANDLE h, LPVOID out, unsigned int outlen);
unsigned int getOid(unsigned int max);
HANDLE opendev(char *dev);

/* Utils */
void error(char *msg);
void print_memory(unsigned long address, char *buffer, unsigned int bytes_to_print);
void get_user_input(char *input, int size);
char **parse_arguments(char *command_line, char arg_delim);

#define NDIS_CRASH_OID OID_PNP_SET_POWER //0xfd010101 
#define NDIS_CRASH_OID2 OID_PM_ADD_PROTOCOL_OFFLOAD //0xfd01010d
#define OID_RECEIVE_FILTER_MOVE_FILTER                  0x00010230  // set only 
#define NDIS_CRASH_OID3 OID_PM_ADD_WOL_PATTERN //0xfd01010a
#define NDIS_CRASH_OID5 OID_RECEIVE_FILTER_CLEAR_FILTER //0x00010228
#define NDIS_CRASH_OID6 OID_RECEIVE_FILTER_FREE_QUEUE //0x00010224


// This is the header for the buffer passed during 0x17009C ndis IOCTL
#define IOCTL_OID_INFO 0x17009C
#define NDIS_OBJECT_TYPE_IOCTL_OID_INFO 0xb9
typedef struct _NDIS_OID_INFO_OBJECT {
	NDIS_OBJECT_HEADER Header;
	//Type is 0xB9
	// Revision is 1
	// Size is 0x2C

	DWORD NdisRequestType; // This can be 0, 1, 2, or 0x0C			 
		/*
		NdisRequestType field:

		This value affects how the operation is going to happen.
		If is set to 0 or 2:
		then ndis sets the InOutBuffSize to OutputBuffLen - PayloadOffset and zero-outs the InOutBuffer in the InternalQuerySet parameter.
		If is set to 1:
		then ndis set InOutBuffSize to InputLen - PayloadOffset, it does not zero outs anything
		If is set to 0x0C:
		then ndis set InOutBuffSize to InputLen - PayloadOffset, Sets InternalQuerySet.UnkSize to OutputBuffLen - AuxLen and Sets InternalQuerySet.UnkVal to [Inputbuff+0x10]
		*/

	DWORD PortNumber; // This sets the PortNumber field of InternalQuerySet
	DWORD OID; // This is the OID for which to perform the call
	DWORD MethodId; // This sets the methodId of the NDIS_OID_REQUEST when RequestType is Method (AdminOnly)
	DWORD Timeout; // This sets Timeoud field of the InternalQUerySet -> goes in the range 0x00-0x3C
	DWORD OutUnkSize;
	// This holds the value of InternalQuerySet.UnkSize after the call of ndisQuerySetMiniport when Operation is 0 or 2
	// If NdisRequestType is 0x0C then this holds InternalQuerySet.Fill04 value
	DWORD OutUnkSize2;
	// This holds the value of InternalQuerySet.UnkSize after the call of ndisQuerySetMiniport when Operation is 1
	// If NdisRequestType is 0x0C then this holds InternalQuerySet.Fill051 value
	DWORD OutUnkVal;
	// This holds the value of InternalQuerySet.UnkVal after the call of ndisQuerySetMiniport
	// If NdisRequestType is 0x0C then this holds InternalQuerySet.fill052 value

	DWORD OutStatus; // This holds the EAX result of the call to ndisQuerySetMiniport
	DWORD PayloadOffset; // This value indicates where the data for the operation starts
		/*
		inputLen >= 0x2C
		OutputLen >= 0x2C
		PayloadOffset >= 0x2C
		PayloadOffset <= min(inputLen,OutputLen) // ndis checks this, so we cannot indicate a payloadOffset that it's out of bounds
		InternalQuerySet.InOutBuff = IRP.AssociatedIrp.SystemBuffer + PayloadOffset
		*/

} NDIS_OID_INFO_OBJECT, *PNDIS_OID_INFO_OBJECT;




typedef struct _HEADER_REQUEST_METHOD {
	DWORD OID;
	DWORD UnkDw1;
	DWORD UnkDw2;
} HEADER_REQUEST_METHOD, *PHEADER_REQUEST_METHOD;



#define IOCTL_NDIS_REQUEST_METHOD IOCTL_NDIS_RESERVED4 



typedef struct _NDIS_INTERNAL_IOCTL {
	char name[256];
	DWORD Ioctl;
} NDIS_INTERNAL_IOCTL, *PNDIS_INTERNAL_IOCTL;

