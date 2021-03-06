#include <Windows.h>
#include <stdio.h>
#include <string.h>

VOID ExceptionHandler();
BOOL IsPEFile(PDWORD pPeFile, DWORD fileSize);
PDWORD PDWInitAlloc(PDWORD pDst, DWORD allocSize);


int main(int argc, char** argv)
{
	HANDLE hFile = NULL;
	HANDLE hDropFile = NULL;
	DWORD fileSize = 0;
	DWORD lpNumberOfBytesReadWrite = 0;

	PDWORD pPEImg = NULL;
	PDWORD pNTHeader = NULL;
	PDWORD pOptionalHeader = NULL;
	PDWORD pIterSectionHeader = NULL;
	PDWORD pDst = NULL;
	PDWORD pSrc = NULL;
	PDWORD pExtraSectionStart = NULL;

	char arrCurPath[MAX_PATH] = { NULL, };
	char arrSectionName[MAX_PATH] = { NULL, };
	char arrDropPath[MAX_PATH] = { NULL, };
	char arrOriginalFileName[MAX_PATH] = { NULL, };

	unsigned char numberOfSections = 0;
	unsigned char sizeOfOptionalHeader = 0;
	unsigned char cnt = 0;
	unsigned int sizeOfRawData = 0;
	unsigned int pointerToRawData = 0;
	unsigned int extraSectionStart = 0; 
	unsigned int extraSectionSize = 0;


	if (argc != 2)
	{
		printf(" [!] Usage: ExtractPESections.exe [Target PE file]\n");
		return -1;
	}
	
	//	Open target file
	hFile = CreateFile(argv[1], GENERIC_READ, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		ExceptionHandler();

	//	Get file size
	fileSize = GetFileSize(hFile, NULL);
	if (fileSize <= 0)
	{
		printf(" [!] FILE SIZE IS ABNORMAL: %08d\n", fileSize);
		ExceptionHandler();
	}

	//	Set memory area for load PE file
	pPEImg = PDWInitAlloc(pPEImg, fileSize);

	//	Read file
	if (!ReadFile(hFile, pPEImg, fileSize, &lpNumberOfBytesReadWrite, NULL))
		ExceptionHandler();
	
	//	Check PE file format
	if (!IsPEFile(pPEImg, fileSize))
		ExceptionHandler();

	//	Get PE Info.
	pNTHeader = (PDWORD)((PBYTE)pPEImg + *((PDWORD)(((PBYTE)pPEImg) + 0x3C)));
	numberOfSections = *(PWORD)((PBYTE)pNTHeader + 0x06);
	sizeOfOptionalHeader = *(PWORD)((PBYTE)pNTHeader + 0x14);
	pOptionalHeader = (PDWORD)((PBYTE)pNTHeader + 0x18);
	pIterSectionHeader = (PDWORD)((PBYTE)pOptionalHeader + sizeOfOptionalHeader);
		
	//	Set target file path
	if(strrchr(argv[1], '\\'))
		strncpy(arrOriginalFileName, strrchr(argv[1], '\\'), strlen(strrchr(argv[1], '\\')));
	else
		memcpy(arrOriginalFileName, argv[1], MAX_PATH);
	

	//	Separate sections as much as numberOfSections
	//	Create/Write dump files
	for (cnt = 0; cnt < (numberOfSections + 1); cnt++)
	{
		//	Get one section's data
		sizeOfRawData = *(PDWORD)((PBYTE)pIterSectionHeader + 0x10);
		pointerToRawData = *(PDWORD)((PBYTE)pIterSectionHeader + 0x14);
		
		//	Get header data
		if (cnt == 0)
		{
			//	Read data until first pointerToRawData
			pDst = PDWInitAlloc(pDst, pointerToRawData);
			memcpy(pDst, pPEImg, pointerToRawData);

			GetCurrentDirectory(MAX_PATH, arrCurPath);
			sprintf(arrDropPath, "%s\\%s_00_HEADER", arrCurPath, arrOriginalFileName);

			//	Create/Write dump file
			hDropFile = CreateFile(arrDropPath, GENERIC_WRITE | GENERIC_READ, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
			if (hDropFile == INVALID_HANDLE_VALUE)
				ExceptionHandler();

			if (!WriteFile(hDropFile, pDst, pointerToRawData, &lpNumberOfBytesReadWrite, NULL))
				ExceptionHandler();

			free(pDst);
			CloseHandle(hDropFile);

			continue;
		}

		//	Allocate one section's memory space
		pDst = PDWInitAlloc(pDst, sizeOfRawData);
		pSrc = (PDWORD)((PBYTE)pPEImg + pointerToRawData);
		
		//	Copy one section's data to [pDst]
		memcpy(pDst, pSrc, sizeOfRawData);

		//	Get section name and set dump file path
		GetCurrentDirectory(MAX_PATH, arrCurPath);
		strncpy(arrSectionName, (char*)pIterSectionHeader, 0x08);
		sprintf(arrDropPath, "%s\\%s_%02d_%s.section", arrCurPath, arrOriginalFileName, cnt, arrSectionName);

		//	Create/Write dump file
		hDropFile = CreateFile(arrDropPath, GENERIC_WRITE | GENERIC_READ, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hDropFile == INVALID_HANDLE_VALUE)
			ExceptionHandler();

		if (!WriteFile(hDropFile, pDst, sizeOfRawData, &lpNumberOfBytesReadWrite, NULL))
			ExceptionHandler();

		//	Move pIterSectionHeader to next section
		pIterSectionHeader = (PDWORD)((PBYTE)pIterSectionHeader + 0x28);

		//	Clear before data
		free(pDst);
		CloseHandle(hDropFile);
	}
	
	extraSectionStart = pointerToRawData + sizeOfRawData;
	pExtraSectionStart = (PDWORD)((PBYTE)pPEImg + (pointerToRawData + sizeOfRawData));

	//	Check extra-section
	if (extraSectionStart < fileSize)
	{
		printf(" [-] Extra section exsited.\n");
		extraSectionSize = fileSize - extraSectionStart;
		
		pDst = PDWInitAlloc(pDst, extraSectionSize);
		memcpy(pDst, pExtraSectionStart, extraSectionSize);

		GetCurrentDirectory(MAX_PATH, arrCurPath);
		sprintf(arrDropPath, "%s\\%s_%02d_EXTRASECTION", arrCurPath, arrOriginalFileName, cnt);

		hDropFile = CreateFile(arrDropPath, GENERIC_WRITE | GENERIC_READ, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hDropFile == INVALID_HANDLE_VALUE)
			ExceptionHandler();

		if (!WriteFile(hDropFile, pDst, extraSectionSize, &lpNumberOfBytesReadWrite, NULL))
			ExceptionHandler();

		free(pDst);
		CloseHandle(hDropFile);
	}

	printf(" [-] Success separating sections...\n");

	//	End normal exit
	free(pPEImg);
	CloseHandle(hFile);

	return 0;
}


VOID ExceptionHandler()
{
	printf(" [!] __ERROR CODE: %08X\n", GetLastError());
	ExitProcess(FALSE);
}

BOOL IsPEFile(PDWORD pPeFile, DWORD fileSize)
{
	PDWORD pE_lfanew = NULL;
	PDWORD pNtHeader = NULL;

	//	Check "MZ" Signature
	if (*(PWORD)pPeFile != 0x5A4D)
		return FALSE;

	//	Get e_lfanew offset and Check range (0x00 < *pE_lfanew < fileSize)
	pE_lfanew = (PDWORD)((PBYTE)pPeFile + 0x3C);
	if ((*pE_lfanew <= 0x00) || (fileSize <= *pE_lfanew))
		return FALSE;

	//	Check "PE" Signature
	pNtHeader = (PDWORD)((PBYTE)pPeFile + *pE_lfanew);
	if (*(PWORD)pNtHeader != 0x4550)
		return FALSE;

	//	Check PE32 (Not support PE32+)
	if (*(PWORD)((PBYTE)pNtHeader + 0x18) != 0x010B)
		return FALSE;

	return TRUE;
}

PDWORD PDWInitAlloc(PDWORD pDst, DWORD allocSize)
{
	pDst = (PDWORD)malloc(allocSize);
	memset(pDst, 0x00, allocSize);

	return pDst;
}