#pragma once
#include <winsock2.h>
#include "common.h"

#pragma comment(lib, "iphlpapi.lib")


BOOL analyze_potential_leaks(DWORD oid, PVOID buffer, UINT size) {
	BOOL result = FALSE;
	int i;
	if (size < 8) {
		return FALSE;
	}
	
	for (i = 0; i < size; i += 8) {
		if (i > size)
			break;
		DWORD64 content = ((DWORD64 *)buffer)[i];		
		if ((content >= 0xFFFF800000000000 && content <= 0xFFFFFFFFFFFFFFFF) && content != 0xFFFFFFFFFFFFFFFF)
			printf("\nOID: %08x, LEAK? %i: %p\n", oid, i, content);
		result = TRUE;		
	}

	return result;
}


void InitializeDeltaFuzz(UINT32 seed) {
	CreateFuzzerObject(&g_fuzzer, 0, TRUE, FALSE);
}

BOOL GetInformationFromAdapters(WCHAR *matchDesc, char *pOutAdapterStr) {
	DWORD outSize = 0;
	PIP_ADAPTER_ADDRESSES pAddresses = NULL;
	ULONG status = 0;
	BOOL result = FALSE;
	status = GetAdaptersAddresses(NULL, NULL, NULL, pAddresses, &outSize);
	if (status == ERROR_BUFFER_OVERFLOW) {
		pAddresses = (PIP_ADAPTER_ADDRESSES) MALLOC(outSize);
		PIP_ADAPTER_ADDRESSES pCurrAddresses = NULL;
		status = GetAdaptersAddresses(NULL, NULL, NULL, pAddresses, &outSize);
		pCurrAddresses = pAddresses;
		while (pCurrAddresses) {
			if (matchDesc == NULL || pOutAdapterStr == NULL) {
				printf("Description: %S\n", pCurrAddresses->Description);
				printf("Adapter: %s\n", pCurrAddresses->AdapterName);			
				printf("FriendlyName: %S\n", pCurrAddresses->FriendlyName);
				puts("-------------\n");
			}
			else {
				//printf("MatchDesc: %S - Description: %S\n", matchDesc, pCurrAddresses->Description);
				if (wcsstr(pCurrAddresses->Description, matchDesc)) {
					memset(pOutAdapterStr, 0x00, 256);
					memcpy(pOutAdapterStr, pCurrAddresses->AdapterName, strlen(pCurrAddresses->AdapterName));	
					result = TRUE;
					break;
				}
			}
			pCurrAddresses = pCurrAddresses->Next;
		}
	}
	FREE(pAddresses);
	return result;
}

HANDLE opendev(char *dev) {
	char buf[1024];
	sprintf_s(buf, sizeof(buf), "\\\\.\\%s", dev);	
	HANDLE h = CreateFileA(buf, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	return h;
}

//IOCTL_NDIS_QUERY_GLOBAL_STATS 
void enum_oids(HANDLE h) {
	char in[5];
	char out[100000];

	int oid = OID_GEN_SUPPORTED_LIST;
	memcpy(in, &oid, 4);
	DWORD ret = 0;
	BOOL r = DeviceIoControl(h, IOCTL_NDIS_QUERY_GLOBAL_STATS, in, 4, out, sizeof(out), &ret, NULL);
	if (!r) {
		printf("-> Error: DeviceIoControl() failed\n");
		printf("  -> code: %08x\n", GetLastError());
		return;
	}

	printf("-> Supported oids:\n");
	int i;
	unsigned int *uip = (unsigned int *)out;
	for (i = 0; i < ret / 4; i++) {
		printf("  -> [%d] 0x%x\n", i, *uip);
		uip++;
	}
}

DWORD getSupportedList(HANDLE h, LPVOID out, unsigned int outlen) {
	char in[5];

	int oid = OID_GEN_SUPPORTED_LIST;
	memcpy(in, &oid, 4);
	DWORD ret = 0;
	BOOL r = DeviceIoControl(h, IOCTL_NDIS_QUERY_GLOBAL_STATS, in, 4, out, outlen, &ret, NULL);
	if (!r) {
		printf("DeviceIoControl() failed\n");
		printf("getlasterror: 0x%x\n", GetLastError());
		return 0;
	}

	return ret / 4;

}

unsigned int getOid(unsigned int max) {
	unsigned int idx = rand() % max;
	return idx;
}


void fuzz_ioctl_query_stats(HANDLE h, UINT iterations, BOOL nonull) {
	unsigned char oidlist[100000];
	unsigned char outbuf[10000];
	unsigned char inbuf[5];
	unsigned int len = 0;
	int oid = 0;
	printf("-> oid var: %p - len: %p - buff: %p\n", &oid, &len, outbuf);

	Sleep(3000);
	DWORD nrOfOids = getSupportedList(h, oidlist, sizeof(oidlist));
	if (!nrOfOids) {
		return;
	}
	
	unsigned int *oids = (unsigned int *)oidlist;
	unsigned int idx;

	unsigned int i = 0;
	if (iterations == 0) {
		iterations = 0xFFFFFFFF;
	}

	while (i < iterations) {
	
		idx = getOid(nrOfOids);
		oid = oids[idx];
		
		len = g_fuzzer->get_fuzzy_len(g_fuzzer, sizeof(outbuf));
		if (nonull) {
			while (len == 0) {
				len = g_fuzzer->get_fuzzy_len(g_fuzzer, sizeof(outbuf));
			}
		}

		g_fuzzer->fuzz_blob(g_fuzzer, (UCHAR *)outbuf, len);
		g_fuzzer->fuzz_blob(g_fuzzer, (UCHAR *)0, 0x1000);

		memcpy(inbuf, &oid, 4);
		DWORD ret = 0;

		BOOL r = DeviceIoControl(h, IOCTL_NDIS_QUERY_GLOBAL_STATS, inbuf, 4, outbuf, len, &ret, NULL);
		printf("\r    -> oid: %08x - len: %d", oid, len);

		if (iterations != 0xFFFFFFFF) {
			i++;
		}
	}

	return;
}

void fuzz_analyze_leaks(HANDLE h, UINT iterations) {
	unsigned char oidlist[100000];
	unsigned char outbuf[10000];
	unsigned int len = 0;
	int oid = 0;
	printf("-> Super dummy pointer leak analyzer...\n");

	DWORD nrOfOids = getSupportedList(h, oidlist, sizeof(oidlist));
	if (!nrOfOids) {
		return;
	}

	unsigned int *oids = (unsigned int *)oidlist;
	unsigned int idx;

	unsigned int i = 0;
	if (iterations == 0) {
		iterations = 0xFFFFFFFF;
	}

	while (i < iterations) {

		idx = getOid(nrOfOids);
		oid = oids[idx];

		len = 0;
		while (len == 0) {
			len = g_fuzzer->get_fuzzy_len(g_fuzzer, sizeof(outbuf));
		}

		DWORD ret = 0;

		memset(outbuf, 0x00, len);
		BOOL r = DeviceIoControl(h, IOCTL_NDIS_QUERY_GLOBAL_STATS, &oid, 4, outbuf, len, &ret, NULL);
		printf("\r    -> oid: %08x - len: %d", oid, len);

		analyze_potential_leaks(oid, outbuf, len);

		if (iterations != 0xFFFFFFFF) {
			i++;
		}

	}

	return;
}

void fuzz_oid(HANDLE h, unsigned int oid, UINT iterations, BOOL nonull) {
	unsigned char outbuf[10000];

	int i = 0;
	if (iterations == 0) {
		iterations = 0xFFFFFFFF;
	}
	while (i < iterations) {
		unsigned int len = g_fuzzer->get_fuzzy_len(g_fuzzer, sizeof(outbuf));
		if (nonull) {
			while (len == 0) {
				len = g_fuzzer->get_fuzzy_len(g_fuzzer, sizeof(outbuf));
			}
		}

		g_fuzzer->fuzz_blob(g_fuzzer, (UCHAR *) outbuf, len);

		DWORD ret = 0;
		
		BOOL r = DeviceIoControl(h, IOCTL_NDIS_QUERY_GLOBAL_STATS, &oid, 4, outbuf, len, &ret, NULL);
		printf("oid: 0x%x\tr: %d\tlen: %d\tretlen: %d\n", oid, r, len, ret);

		if (iterations != 0xFFFFFFFF) {
			i++;
		}
	}
	return;
}

//IOCTL_NDIS_QUERY_GLOBAL_STATS 
void enum_oids_fuzz(HANDLE h, UINT iterations, BOOL nonull) {
	char in[5];
	char out[100000];
	int oid = OID_GEN_SUPPORTED_LIST;
	memcpy(in, &oid, 4);
	DWORD ret = 0;
	BOOL r = DeviceIoControl(h, IOCTL_NDIS_QUERY_GLOBAL_STATS, in, 4, out, sizeof(out), &ret, NULL);
	if (!r) {
		printf("-> Error: DeviceIoControl() failed\n");
		printf("  -> code: %08x\n", GetLastError());
		return;
	}
	int i;
	unsigned int* uip = (unsigned int*)out;
	for (i = 0; i < ret / 4; i++) {
		printf("  -> Fuzzing OID: [%d] 0x%x\n", i, *uip);
		fuzz_oid(h, *uip, iterations, nonull);
		uip++;
	}
	return *uip;
}

void fuzz_ioctl_oid_info(HANDLE h, UINT iterations) {
	unsigned char oidlist[100000];
	unsigned int *oids = (unsigned int *)oidlist;
	DWORD nrOfOids = getSupportedList(h, oidlist, sizeof(oidlist));
	
	DWORD headerSize = sizeof(NDIS_OID_INFO_OBJECT);
	PNDIS_OID_INFO_OBJECT pHeader = NULL;
	int buffSize = 0x10000;
	PVOID inBuff = MALLOC(buffSize);
	PVOID outBuff = MALLOC(buffSize);
	int oid = 0;
	DWORD inLen, outLen = 0;
	printf("-> oid var: %p - inLen: %p - outLen: %p - inbuff: %p - outbuff: %p\n",
		&oid, &inLen, &outLen, inBuff, outBuff);

	int i = 0;
	if (iterations == 0) {
		iterations = 0xFFFFFFFF;
	}
	while (i < iterations) {
	
		inLen = g_fuzzer->get_fuzzy_len(g_fuzzer, (0x1000 - headerSize)) + headerSize;
		outLen = g_fuzzer->get_fuzzy_len(g_fuzzer, (0x1000 - headerSize)) + headerSize;
		
		unsigned int idx = getOid(nrOfOids);
		oid = oids[idx];

		g_fuzzer->fuzz_blob(g_fuzzer, (UCHAR *) inBuff, inLen);
		g_fuzzer->fuzz_blob(g_fuzzer, (UCHAR *) outBuff, outLen);

		pHeader = (PNDIS_OID_INFO_OBJECT) inBuff;
		pHeader->Header.Type = 0xB9;
		pHeader->Header.Revision = 1;
		pHeader->Header.Size = 0x2C;
		pHeader->NdisRequestType = NdisRequestQueryInformation;
		pHeader->OID = oid;

		g_fuzzer->fuzz_blob(g_fuzzer, (UCHAR *)&pHeader->PortNumber, sizeof(DWORD));
		//pHeader->PortNumber = 0x00;

		pHeader->Timeout = g_fuzzer->get_fuzzy_len(g_fuzzer, 0x3C);
		g_fuzzer->fuzz_blob(g_fuzzer, (UCHAR *)&pHeader->MethodId, sizeof(DWORD));
		
		if (inLen == headerSize || outLen == headerSize) {
			pHeader->PayloadOffset = headerSize;
		}
		else if (inLen <= outLen) {
			pHeader->PayloadOffset = g_fuzzer->get_fuzzy_len(g_fuzzer, (inLen - headerSize)) + headerSize;
		}
		else {
			pHeader->PayloadOffset = g_fuzzer->get_fuzzy_len(g_fuzzer, (outLen - headerSize)) + headerSize;
		}
		/*
		inputLen >= 0x2C
		OutputLen >= 0x2C
		PayloadOffset >= 0x2C
		PayloadOffset <= min(inputLen,OutputLen) // ndis checks this, so we cannot indicate a payloadOffset that it's out of bounds
		InternalQuerySet.InOutBuff = IRP.AssociatedIrp.SystemBuffer + PayloadOffset
		*/

		DWORD ret = 0;
		BOOL r = DeviceIoControl(h, IOCTL_OID_INFO, inBuff, inLen, outBuff, outLen, &ret, NULL);
		printf(
			"\r    -> oid: %08x\tr: %d\tlen: %d\tretlen: %d",
			oid,
			r,
			outLen,
			ret
		);

		if (iterations != 0xFFFFFFFF) {
			i++;
		}
	}

	return;
}

// These seem to be the supported ones
DWORD Request_Method_OID_Array[] = {
	OID_RECEIVE_FILTER_QUEUE_PARAMETERS, //0x10226,
	OID_RECEIVE_FILTER_ENUM_FILTERS, //0x10229,
	OID_RECEIVE_FILTER_PARAMETERS, //0x1022A,
	OID_NIC_SWITCH_PARAMETERS, //0x10238,
	OID_NIC_SWITCH_VPORT_PARAMETERS, //0x10242,
	OID_NIC_SWITCH_ENUM_VPORTS, //0x10243,
	OID_NIC_SWITCH_VF_PARAMETERS, //0x10247,
	OID_NIC_SWITCH_ENUM_VFS, //0x10248
};


void fuzz_ioctl_method(HANDLE h, UINT iterations) {
	if (h == (HANDLE)-1 || h == NULL) {
		error("Handle wasn't opened\n");
	}

	// Starts here	
	DWORD headerSize = sizeof(HEADER_REQUEST_METHOD);
	int buffSize = 0x10000;
	PVOID inBuff = MALLOC(buffSize);
	PVOID outBuff = MALLOC(buffSize);
	PHEADER_REQUEST_METHOD pHeader = (PHEADER_REQUEST_METHOD)inBuff;
	DWORD inLen = 0;
	DWORD outLen = 0;
	int oid = 0;

	printf("oid var: %p - inLen: %p - outLen: %p - inBuff: %p - outBuff\n",
		&oid, &inLen, &outLen, inBuff, outBuff);

	Sleep(3000);

	int i = 0;
	if (iterations == 0) {
		iterations = 0xFFFFFFFF;
	}
	while (i < iterations) {

		inLen = g_fuzzer->get_fuzzy_len(g_fuzzer, (buffSize - sizeof(HEADER_REQUEST_METHOD))) + sizeof(HEADER_REQUEST_METHOD);
		outLen = g_fuzzer->get_fuzzy_len(g_fuzzer, buffSize);

		g_fuzzer->fuzz_blob(g_fuzzer, (UCHAR *)inBuff, inLen);
		g_fuzzer->fuzz_blob(g_fuzzer, (UCHAR *)outBuff, outLen);

		pHeader->OID = Request_Method_OID_Array[g_fuzzer->get_random(g_fuzzer) %
			(sizeof(Request_Method_OID_Array) / sizeof(Request_Method_OID_Array[0]))];

		DWORD ret = 0;
		BOOL r = DeviceIoControl(h, IOCTL_NDIS_REQUEST_METHOD, inBuff, inLen, outBuff, outLen, &ret, NULL);
		printf("\roid: 0x%x\tr: %d\tlen: %d\tretlen: %d", oid, r, outLen, ret);

		if (iterations != 0xFFFFFFFF) {
			i++;
		}
	}

	return;
}

void fuzz_target(int argc, char **argv) {
	// argv: { querystats , <handle>, <iterations> <nonull> }
	UINT iterations = 0;
	BOOL nonull = FALSE;
	if (argc >= 2) {
		if (argc >= 3) {
			if (!strcmp(argv[2], "nonull")) {
				nonull = TRUE;
			}
			else {
				iterations = strtoul(argv[2], NULL, 10);
			}
			if (argc == 4) {
				if (!strcmp(argv[3], "nonull")) {
					nonull = TRUE;
				}
			}
		} 
		HANDLE h = strtoul(argv[1], NULL, 16);
		if (!strcmp(argv[0], "querystats")) {			
			fuzz_ioctl_query_stats(h, iterations, nonull);
		}
		else if (!strcmp(argv[0], "oidinfo")) {		
			fuzz_ioctl_oid_info(h, iterations);
		}
		else if (!strcmp(argv[0], "method")) {
			fuzz_ioctl_method(h, iterations);
		}
		else if (!strcmp(argv[0], "leaks")) {
			fuzz_analyze_leaks(h, iterations);
		}		
	}
}


void show_help() {
	printf("Commands:\n");
	printf("list -> list all the interfaces\n");
	printf("open {GUID} -> opens a handle to de miniport\n");
	printf("enumoids <handle>\n");
	printf("fuzz querystats <handle> <optional:iterations> <optional:nonull>\n");
	printf("fuzz oidinfo <handle> <optional:iterations> <optional:nonull>\n");
	printf("fuzz method <handle> <optional:iterations> <optional:nonull>\n");
	printf("fuzz leaks <handle> <optional:iterations>\n");
	//fuzzoid <handle> <oid> <iterations> <nonull>
	printf("fuzzoid <handle> <oid> <optional:iterations>\n");
	printf("fuzzoids <handle> <optional:iterations> <optional:nonull>\n");
	printf("--\n");
}


int  main() {
	InitializeDeltaFuzz(NULL);
	char command_line[512];
	char **args;
	BOOL exit = FALSE;

	HANDLE h;
	while (exit != TRUE) {
		printf(">>> ");
		fflush(stdout);
		get_user_input(command_line, sizeof(command_line));
		if (strlen(command_line) == 0) {
			continue;
		}
		args = parse_arguments(command_line, ' ');
		int argc = (int)args[0];
		argc--;
		char **argv = &args[1];

		if (!strcmp(argv[0], "list")) {
			GetInformationFromAdapters(NULL, NULL);
		}
		else if (!strcmp(argv[0], "open")) {
			h = opendev((char *)argv[1]);
			if (h == (HANDLE)-1 || h == NULL) {
				printf("-> Error: handle for device %s wasn't opened\n", argv[1]);
			}
			else {
				printf("-> Success: new handle %08x\n", h);
			}
		}
		else if (!strcmp(argv[0], "close")) {			
			if (argc == 2) {
				h = strtoul(argv[1], NULL, 16);
				if (CloseHandle((HANDLE)h)) 
					printf("-> closed handle %08x\n", h);
				else
					printf("-> Error: CloseHandle failed\n", h);
			}
		}
		else if (!strcmp(argv[0], "enumoids")) {
			if (argc == 2) {
				h = strtoul(argv[1], NULL, 16);
				enum_oids(h);
			}
		}
		else if (!strcmp(argv[0], "fuzz")) {
			argc--;
			fuzz_target(argc, &argv[1]);
		}
		else if (!strcmp(argv[0], "fuzzoid")) {
			// fuzzoid <handle> <oid> <iterations> <nonull>
			if (argc >= 3) {
				UINT iterations = 0;
				BOOL nonull = FALSE;
				if (argc >= 4) {
					if (!strcmp(argv[2], "nonull")) {
						nonull = TRUE;
					}
					else {
						iterations = strtoul(argv[2], NULL, 10);
					}
					if (argc == 5) {
						if (!strcmp(argv[3], "nonull")) {
							nonull = TRUE;
						}
					}
				}
				h = strtoul(argv[1], NULL, 16);
				UINT oid = strtoul(argv[2], NULL, 16);
				fuzz_oid(h, oid, iterations, nonull);
			}
		}	
		else if (!strcmp(argv[0], "fuzzoids")) {
			h = strtoul(argv[1], NULL, 16);
			
			if (argc >= 2) {
				UINT iterations = 0;
				BOOL nonull = FALSE;
				if (argc >= 3) {
					if (!strcmp(argv[2], "nonull")) {
						nonull = TRUE;
					}
					else {
						iterations = strtoul(argv[2], NULL, 10);
					}
					if (argc == 4) {
						if (!strcmp(argv[3], "nonull")) {
							nonull = TRUE;
						}
					}

					enum_oids_fuzz(h, iterations, nonull);
				}
			}
		}
	
		else if (!strcmp(argv[0], "?") || !strcmp(argv[0], "help")) {
			show_help();
		}
		else if (!strcmp(argv[0], "exit")) {
			exit = TRUE;
		}
		free(args);
	}

	return 0;
}