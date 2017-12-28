#include <Windows.h>
#include <stdio.h>


VOID ExceptionHandler();
BOOL IsPEFile(PDWORD pPeFile, DWORD fileSize);


int main(int argc, char** argv)
{
	HANDLE hFile = NULL;
	HANDLE hDropFile = NULL;
	DWORD fileSize = 0;
	DWORD lpNumberOfBytesReadWrite = 0;

	PDWORD pNTHeader = NULL;
	PDWORD pOptionalHeader = NULL;
	PDWORD pIterSectionHeader = NULL;
	PDWORD pDst = NULL;
	PDWORD pSrc = NULL;

	char arrCurPath[MAX_PATH] = { NULL, };
	char arrSectionName[MAX_PATH] = { NULL, };
	char arrDropPath[MAX_PATH] = { NULL, };

	unsigned char numberOfSections = 0;
	unsigned char sizeOfOptionalHeader = 0;
	unsigned char cnt = 0;
	unsigned int sizeOfRawData = 0;
	unsigned int pointerToRawData = 0;


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
		printf(" [!] FILE SIZE: 0\n");
		ExceptionHandler();
	}

	//	Set memory area for load file
	const PDWORD pPEImg = (PDWORD)malloc(fileSize);
	memset(pPEImg, 0x00, fileSize);

	//	Read file
	if (!ReadFile(hFile, pPEImg, fileSize, &lpNumberOfBytesReadWrite, NULL))
		ExceptionHandler();


	//	Check PE file format
	if (!IsPEFile(pPEImg, fileSize))
		ExceptionHandler();

	//	Get PE Info.
	pNTHeader = (PDWORD)((PBYTE)pPEImg + *((PBYTE)pPEImg + 0x3C));

	numberOfSections = *(PWORD)((PBYTE)pNTHeader + 0x06);
	sizeOfOptionalHeader = *(PWORD)((PBYTE)pNTHeader + 0x14);
	pOptionalHeader = (PDWORD)((PBYTE)pNTHeader + 0x18);
	pIterSectionHeader = (PDWORD)((PBYTE)pOptionalHeader + sizeOfOptionalHeader);


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
			pDst = (PDWORD)malloc(pointerToRawData);
			memset(pDst, 0x00, pointerToRawData);
			memcpy(pDst, pPEImg, pointerToRawData);

			GetCurrentDirectory(MAX_PATH, arrCurPath);
			sprintf_s(arrDropPath, "%s\\00_HEADER", arrCurPath);

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
		pDst = (PDWORD)malloc(sizeOfRawData);
		pSrc = (PDWORD)((PBYTE)pPEImg + pointerToRawData);
		memset(pDst, 0x00, sizeOfRawData);

		//	Copy one section's data to [pDst]
		memcpy(pDst, pSrc, sizeOfRawData);

		//	Get section name and set dump file path
		GetCurrentDirectory(MAX_PATH, arrCurPath);
		strncpy_s(arrSectionName, (char*)pIterSectionHeader, 0x08);
		sprintf_s(arrDropPath, "%s\\%02d_%s.section", arrCurPath, cnt, arrSectionName);

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

