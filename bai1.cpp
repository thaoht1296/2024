#include <windows.h>
#include <tchar.h> 
#include <iostream>
#include <string>
#include <stdio.h>
#include <strsafe.h>
#include "accctrl.h"
#include "aclapi.h"
#include <strsafe.h>
#pragma comment(lib, "User32.lib")

using namespace std;

void DisplayErrorBox(LPTSTR lpszFunction);
string GetOwnerFile(string file);
BOOL GetCreateTime(string file, LPTSTR lpszString, DWORD dwSize);
BOOL GetLastWriteTime(string file, LPTSTR lpszString, DWORD dwSize);
void GetListFile(string path);


int main(int argc, char** argv)
{

    string dir = "C:\\Users\\thaoht29\\Documents";
    
//    string dir;
//    cout << "Enter path to list files: ";
//    cin >> dir;

    GetListFile(dir);
	
}


void DisplayErrorBox(LPTSTR lpszFunction) 
{ 
    // Retrieve the system error message for the last-error code

    LPVOID lpMsgBuf;
    LPVOID lpDisplayBuf;
    DWORD dw = GetLastError(); 

    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | 
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        dw,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR) &lpMsgBuf,
        0, NULL );

    // Display the error message and clean up

    lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT, 
        (lstrlen((LPCTSTR)lpMsgBuf)+lstrlen((LPCTSTR)lpszFunction)+40)*sizeof(TCHAR)); 
    StringCchPrintf((LPTSTR)lpDisplayBuf, 
        LocalSize(lpDisplayBuf) / sizeof(TCHAR),
        TEXT("%s failed with error %d: %s"), 
        lpszFunction, dw, lpMsgBuf); 
    MessageBox(NULL, (LPCTSTR)lpDisplayBuf, TEXT("Error"), MB_OK); 

    LocalFree(lpMsgBuf);
    LocalFree(lpDisplayBuf);
}


string GetOwnerFile(string file){
	DWORD dwRtnCode = 0;
	PSID pSidOwner = NULL;
	BOOL bRtnBool = TRUE;
	LPTSTR AcctName = NULL;
	LPTSTR DomainName = NULL;
	DWORD dwAcctName = 1, dwDomainName = 1;
	SID_NAME_USE eUse = SidTypeUnknown;
	HANDLE hFile;
	PSECURITY_DESCRIPTOR pSD = NULL;
	string err = "error";
	
	
	// Get the handle of the file object.
	hFile = CreateFile(
	                  file.c_str(),
	                  GENERIC_READ,
	                  FILE_SHARE_READ,
	                  NULL,
	                  OPEN_EXISTING,
	                  FILE_ATTRIBUTE_NORMAL,
	                  NULL);
	
	// Check GetLastError for CreateFile error code.
	if (hFile == INVALID_HANDLE_VALUE) {
	          DWORD dwErrorCode = 0;
	
	          dwErrorCode = GetLastError();
	          _tprintf(TEXT("CreateFile error = %d\n"), dwErrorCode);
	          return err;
	}
	
	
	
	// Get the owner SID of the file.
	dwRtnCode = GetSecurityInfo(
	                  hFile,
	                  SE_FILE_OBJECT,
	                  OWNER_SECURITY_INFORMATION,
	                  &pSidOwner,
	                  NULL,
	                  NULL,
	                  NULL,
	                  &pSD);
	
	// Check GetLastError for GetSecurityInfo error condition.
	if (dwRtnCode != ERROR_SUCCESS) {
	          DWORD dwErrorCode = 0;
	
	          dwErrorCode = GetLastError();
	          _tprintf(TEXT("GetSecurityInfo error = %d\n"), dwErrorCode);
	          return err;
	}
	
	// First call to LookupAccountSid to get the buffer sizes.
	bRtnBool = LookupAccountSid(
	                  NULL,           // local computer
	                  pSidOwner,
	                  AcctName,
	                  (LPDWORD)&dwAcctName,
	                  DomainName,
	                  (LPDWORD)&dwDomainName,
	                  &eUse);
	
	// Reallocate memory for the buffers.
	AcctName = (LPTSTR)GlobalAlloc(
	          GMEM_FIXED,
	          dwAcctName * sizeof(wchar_t));
	
	// Check GetLastError for GlobalAlloc error condition.
	if (AcctName == NULL) {
	          DWORD dwErrorCode = 0;
	
	          dwErrorCode = GetLastError();
	          _tprintf(TEXT("GlobalAlloc error = %d\n"), dwErrorCode);
	          return err;
	}
	
    DomainName = (LPTSTR)GlobalAlloc(
           GMEM_FIXED,
           dwDomainName * sizeof(wchar_t));

    // Check GetLastError for GlobalAlloc error condition.
    if (DomainName == NULL) {
          DWORD dwErrorCode = 0;

          dwErrorCode = GetLastError();
          _tprintf(TEXT("GlobalAlloc error = %d\n"), dwErrorCode);
          return err;

    }

    // Second call to LookupAccountSid to get the account name.
    bRtnBool = LookupAccountSid(
          NULL,                   // name of local or remote computer
          pSidOwner,              // security identifier
          AcctName,               // account name buffer
          (LPDWORD)&dwAcctName,   // size of account name buffer 
          DomainName,             // domain name
          (LPDWORD)&dwDomainName, // size of domain name buffer
          &eUse);                 // SID type

    // Check GetLastError for LookupAccountSid error condition.
    if (bRtnBool == FALSE) {
          DWORD dwErrorCode = 0;

          dwErrorCode = GetLastError();

          if (dwErrorCode == ERROR_NONE_MAPPED)
              _tprintf(TEXT
                  ("Account owner not found for specified SID.\n"));
          else 
              _tprintf(TEXT("Error in LookupAccountSid.\n"));
          return err;

    } else if (bRtnBool == TRUE) 

    // Print the account name.
//    _tprintf(TEXT("Account owner = %s\n"), AcctName);
    return AcctName;
        
}

BOOL GetCreateTime(string file, LPTSTR lpszString, DWORD dwSize){
	FILETIME ftCreate, ftAccess, ftWrite;
    SYSTEMTIME stUTC, stLocal;
    DWORD dwRet;
    HANDLE hFile;

	hFile = CreateFile(file.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, 0, NULL);
    
	if(hFile == INVALID_HANDLE_VALUE)
    {
        printf("CreateFile failed with %d\n", GetLastError());
        return 0;
    }  
    // Retrieve the file times for the file.
    if (!GetFileTime(hFile, &ftCreate, &ftAccess, &ftWrite))
        return FALSE;

    // Convert the last-write time to local time.
    FileTimeToSystemTime(&ftCreate, &stUTC);
    SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal);

    // Build a string showing the date and time.
    dwRet = StringCchPrintf(lpszString, dwSize, 
        TEXT("%02d/%02d/%d  %02d:%02d"),
        stLocal.wMonth, stLocal.wDay, stLocal.wYear,
        stLocal.wHour, stLocal.wMinute);

    if( S_OK == dwRet )
        return TRUE;
    else return FALSE;
}

BOOL GetLastWriteTime(string file, LPTSTR lpszString, DWORD dwSize)
{
    FILETIME ftCreate, ftAccess, ftWrite;
    SYSTEMTIME stUTC, stLocal;
    DWORD dwRet;
    HANDLE hFile;
    
	hFile = CreateFile(file.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL,
    	OPEN_EXISTING, 0, NULL);
    if(hFile == INVALID_HANDLE_VALUE)
    {
        printf("CreateFile failed with %d\n", GetLastError());
        return 0;
    }
    // Retrieve the file times for the file.
    if (!GetFileTime(hFile, &ftCreate, &ftAccess, &ftWrite))
        return FALSE;

    // Convert the last-write time to local time.
    FileTimeToSystemTime(&ftWrite, &stUTC);
    SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal);

    // Build a string showing the date and time.
    dwRet = StringCchPrintf(lpszString, dwSize, 
        TEXT("%02d/%02d/%d  %02d:%02d"),
        stLocal.wMonth, stLocal.wDay, stLocal.wYear,
        stLocal.wHour, stLocal.wMinute);

    if( S_OK == dwRet )
        return TRUE;
    else return FALSE;
}

void GetListFile(string dir){
	WIN32_FIND_DATA ffd;
	LARGE_INTEGER filesize;
	TCHAR szDir[MAX_PATH];
	size_t length_of_arg;
	HANDLE hFind = INVALID_HANDLE_VALUE;
	DWORD dwError=0;
		
	// If the directory is not specified as a command-line argument,
	// print usage.
	
	if(dir.empty())
	{
	  _tprintf(TEXT("\nUsage: %s <directory name>\n"), dir.c_str());
	}
	
	
	
	// Check that the input path plus 3 is not longer than MAX_PATH.
	// Three characters are for the "\*" plus NULL appended below.
	
	StringCchLength(dir.c_str(), MAX_PATH, &length_of_arg);
	
	if (length_of_arg > (MAX_PATH - 3))
	{
	  _tprintf(TEXT("\nDirectory path is too long.\n"));
	}
	
	_tprintf(TEXT("\nTarget directory is %s\n\n"), dir.c_str());
	
	// Prepare string for use with FindFile functions.  First, copy the
	// string to a buffer, then append '\*' to the directory name.
	
	StringCchCopy(szDir, MAX_PATH, dir.c_str());
	StringCchCat(szDir, MAX_PATH, TEXT("\\*"));
	
	// Find the first file in the directory.
	
	hFind = FindFirstFile(szDir, &ffd);
	string filename;
	string fullpath;
	string owner;
	TCHAR szCre[MAX_PATH];
	TCHAR szEdit[MAX_PATH];
	if (INVALID_HANDLE_VALUE == hFind) 
	{
	  DisplayErrorBox(TEXT("FindFirstFile"));
	} 
	
	// List all the files in the directory with some info about them.
	
	do
	{
	  if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
	  {
	     _tprintf(TEXT("%s\t<DIR>\n"), ffd.cFileName);
	  }
	  else
	  {
	     filesize.LowPart = ffd.nFileSizeLow;
	     filesize.HighPart = ffd.nFileSizeHigh;
	     filename = ffd.cFileName;
	     fullpath = dir + "\\" + filename;
	     owner = GetOwnerFile(fullpath);
	     if(GetCreateTime( fullpath, szCre, MAX_PATH ) && GetLastWriteTime( fullpath, szEdit, MAX_PATH )){
	     	cout << filename << "\t" <<filesize.QuadPart<<" bytes \t"<< owner <<"\t"<<szCre<<"\t"<<szEdit <<endl;
		 }
	  }
	}
	while (FindNextFile(hFind, &ffd) != 0);
	
	dwError = GetLastError();
	if (dwError != ERROR_NO_MORE_FILES) 
	{
	  DisplayErrorBox(TEXT("FindFirstFile"));
	}
	
	FindClose(hFind);
}
