// Encrypting_a_File.cpp : Defines the entry point for the console 
// application.
//

#include <tchar.h>
#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include <conio.h>

// Link with the Advapi32.lib file.
#pragma comment (lib, "advapi32")

#define KEYLENGTH  0x00800000
#define ENCRYPT_ALGORITHM CALG_RC4 
#define ENCRYPT_BLOCK_SIZE 8 

bool MyEncryptFile(
	LPTSTR szSource,
	LPTSTR szDestination,
	LPTSTR szPassword);

void MyHandleError(
	LPTSTR psz,
	int nErrorNumber);

int encrypt_file(char* file_name)
{
	//---------------------------------------------------------------
	// Call EncryptFile to do the actual encryption.
	if (MyEncryptFile(file_name, "temp_file.tmp", NULL))
	{
		DeleteFileA(file_name);
		rename("temp_file.tmp", file_name);
		return 1;
	}
	return 0;
}

//-------------------------------------------------------------------
// Code for the function MyEncryptFile called by main.
//-------------------------------------------------------------------
// Parameters passed are:
//  pszSource, the name of the input, a plaintext file.
//  pszDestination, the name of the output, an encrypted file to be 
//   created.
//  pszPassword, either NULL if a password is not to be used or the 
//   string that is the password.
bool MyEncryptFile(
	LPTSTR pszSourceFile,
	LPTSTR pszDestinationFile,
	LPTSTR pszPassword)
{
	//---------------------------------------------------------------
	// Declare and initialize local variables.
	bool fReturn = false;
	HANDLE hSourceFile = INVALID_HANDLE_VALUE;
	HANDLE hDestinationFile = INVALID_HANDLE_VALUE;

	HCRYPTPROV hCryptProv = NULL;
	HCRYPTKEY hKey = NULL;
	HCRYPTKEY hXchgKey = NULL;
	HCRYPTHASH hHash = NULL;

	PBYTE pbKeyBlob = NULL;
	DWORD dwKeyBlobLen;

	PBYTE pbBuffer = NULL;
	DWORD dwBlockLen;
	DWORD dwBufferLen;
	DWORD dwCount;

	//---------------------------------------------------------------
	// Open the source file. 
	hSourceFile = CreateFile(
		pszSourceFile,
		FILE_READ_DATA,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (INVALID_HANDLE_VALUE != hSourceFile)
	{
		;
	}
	else
	{
		;
		goto Exit_MyEncryptFile;
	}

	//---------------------------------------------------------------
	// Open the destination file. 
	hDestinationFile = CreateFile(
		pszDestinationFile,
		FILE_WRITE_DATA,
		FILE_SHARE_READ,
		NULL,
		OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (INVALID_HANDLE_VALUE != hDestinationFile)
	{
		;
	}
	else
	{
		;
		goto Exit_MyEncryptFile;
	}

	//---------------------------------------------------------------
	// Get the handle to the default provider. 
	if (CryptAcquireContext(
		&hCryptProv,
		NULL,
		MS_ENHANCED_PROV,
		PROV_RSA_FULL,
		0))
	{
		;
	}
	else
	{
		;
		goto Exit_MyEncryptFile;
	}

	//---------------------------------------------------------------
	// Create the session key.
	if (!pszPassword || !pszPassword[0])
	{
		//-----------------------------------------------------------
		// No password was passed.
		// Encrypt the file with a random session key, and write the 
		// key to a file. 

		//-----------------------------------------------------------
		// Create a random session key. 
		if (CryptGenKey(
			hCryptProv,
			ENCRYPT_ALGORITHM,
			KEYLENGTH | CRYPT_EXPORTABLE,
			&hKey))
		{
			;
		}
		else
		{
			;
			goto Exit_MyEncryptFile;
		}

		//-----------------------------------------------------------
		// Get the handle to the exchange public key. 
		if (CryptGetUserKey(
			hCryptProv,
			AT_KEYEXCHANGE,
			&hXchgKey))
		{
			;
		}
		else
		{
			if (NTE_NO_KEY == GetLastError())
			{
				// No exchange key exists. Try to create one.
				if (!CryptGenKey(
					hCryptProv,
					AT_KEYEXCHANGE,
					CRYPT_EXPORTABLE,
					&hXchgKey))
				{
					;
					goto Exit_MyEncryptFile;
				}
			}
			else
			{
				;
				goto Exit_MyEncryptFile;
			}
		}

		//-----------------------------------------------------------
		// Determine size of the key BLOB, and allocate memory. 
		if (CryptExportKey(
			hKey,
			hXchgKey,
			SIMPLEBLOB,
			0,
			NULL,
			&dwKeyBlobLen))
		{
			;
		}
		else
		{
			;
			goto Exit_MyEncryptFile;
		}

		if (pbKeyBlob = (BYTE *)malloc(dwKeyBlobLen))
		{
			;
		}
		else
		{
			;
			goto Exit_MyEncryptFile;
		}

		//-----------------------------------------------------------
		// Encrypt and export the session key into a simple key 
		// BLOB. 
		if (CryptExportKey(
			hKey,
			hXchgKey,
			SIMPLEBLOB,
			0,
			pbKeyBlob,
			&dwKeyBlobLen))
		{
			;
		}
		else
		{
			;
			goto Exit_MyEncryptFile;
		}

		//-----------------------------------------------------------
		// Release the key exchange key handle. 
		if (hXchgKey)
		{
			if (!(CryptDestroyKey(hXchgKey)))
			{
				;
				goto Exit_MyEncryptFile;
			}

			hXchgKey = 0;
		}

		//-----------------------------------------------------------
		// Write the size of the key BLOB to the destination file. 
		if (!WriteFile(
			hDestinationFile,
			&dwKeyBlobLen,
			sizeof(DWORD),
			&dwCount,
			NULL))
		{
			;
			goto Exit_MyEncryptFile;
		}
		else
		{
			;
		}

		//-----------------------------------------------------------
		// Write the key BLOB to the destination file. 
		if (!WriteFile(
			hDestinationFile,
			pbKeyBlob,
			dwKeyBlobLen,
			&dwCount,
			NULL))
		{
			;
			goto Exit_MyEncryptFile;
		}
		else
		{
			;
		}

		// Free memory.
		free(pbKeyBlob);
	}
	else
	{

		//-----------------------------------------------------------
		// The file will be encrypted with a session key derived 
		// from a password.
		// The session key will be recreated when the file is 
		// decrypted only if the password used to create the key is 
		// available. 

		//-----------------------------------------------------------
		// Create a hash object. 
		if (CryptCreateHash(
			hCryptProv,
			CALG_MD5,
			0,
			0,
			&hHash))
		{
			;
		}
		else
		{
			;
			goto Exit_MyEncryptFile;
		}

		//-----------------------------------------------------------
		// Hash the password. 
		if (CryptHashData(
			hHash,
			(BYTE *)pszPassword,
			lstrlen(pszPassword),
			0))
		{
			;
		}
		else
		{
			;
			goto Exit_MyEncryptFile;
		}

		//-----------------------------------------------------------
		// Derive a session key from the hash object. 
		if (CryptDeriveKey(
			hCryptProv,
			ENCRYPT_ALGORITHM,
			hHash,
			KEYLENGTH,
			&hKey))
		{
			;
		}
		else
		{
			;
			goto Exit_MyEncryptFile;
		}
	}

	//---------------------------------------------------------------
	// The session key is now ready. If it is not a key derived from 
	// a  password, the session key encrypted with the private key 
	// has been written to the destination file.

	//---------------------------------------------------------------
	// Determine the number of bytes to encrypt at a time. 
	// This must be a multiple of ENCRYPT_BLOCK_SIZE.
	// ENCRYPT_BLOCK_SIZE is set by a #define statement.
	dwBlockLen = 1000 - 1000 % ENCRYPT_BLOCK_SIZE;

	//---------------------------------------------------------------
	// Determine the block size. If a block cipher is used, 
	// it must have room for an extra block. 
	if (ENCRYPT_BLOCK_SIZE > 1)
	{
		dwBufferLen = dwBlockLen + ENCRYPT_BLOCK_SIZE;
	}
	else
	{
		dwBufferLen = dwBlockLen;
	}

	//---------------------------------------------------------------
	// Allocate memory. 
	if (pbBuffer = (BYTE *)malloc(dwBufferLen))
	{
		;
	}
	else
	{
		;
		goto Exit_MyEncryptFile;
	}

	//---------------------------------------------------------------
	// In a do loop, encrypt the source file, 
	// and write to the source file. 
	bool fEOF = FALSE;
	do
	{
		//-----------------------------------------------------------
		// Read up to dwBlockLen bytes from the source file. 
		if (!ReadFile(
			hSourceFile,
			pbBuffer,
			dwBlockLen,
			&dwCount,
			NULL))
		{
			;
			goto Exit_MyEncryptFile;
		}

		if (dwCount < dwBlockLen)
		{
			fEOF = TRUE;
		}

		//-----------------------------------------------------------
		// Encrypt data. 
		if (!CryptEncrypt(
			hKey,
			NULL,
			fEOF,
			0,
			pbBuffer,
			&dwCount,
			dwBufferLen))
		{
			;
			goto Exit_MyEncryptFile;
		}

		//-----------------------------------------------------------
		// Write the encrypted data to the destination file. 
		if (!WriteFile(
			hDestinationFile,
			pbBuffer,
			dwCount,
			&dwCount,
			NULL))
		{
			;
			goto Exit_MyEncryptFile;
		}

		//-----------------------------------------------------------
		// End the do loop when the last block of the source file 
		// has been read, encrypted, and written to the destination 
		// file.
	} while (!fEOF);

	fReturn = true;

Exit_MyEncryptFile:
	//---------------------------------------------------------------
	// Close files.
	if (hSourceFile)
	{
		CloseHandle(hSourceFile);
	}

	if (hDestinationFile)
	{
		CloseHandle(hDestinationFile);
	}

	//---------------------------------------------------------------
	// Free memory. 
	if (pbBuffer)
	{
		free(pbBuffer);
	}


	//-----------------------------------------------------------
	// Release the hash object. 
	if (hHash)
	{
		if (!(CryptDestroyHash(hHash)))
		{
			;
		}

		hHash = NULL;
	}

	//---------------------------------------------------------------
	// Release the session key. 
	if (hKey)
	{
		if (!(CryptDestroyKey(hKey)))
		{
			;
		}
	}

	//---------------------------------------------------------------
	// Release the provider handle. 
	if (hCryptProv)
	{
		if (!(CryptReleaseContext(hCryptProv, 0)))
		{
			;
		}
	}

	return fReturn;
} // End Encryptfile.


//-------------------------------------------------------------------
//  This example uses the function MyHandleError, a simple error
//  handling function, to print an error message to the  
//  standard error (stderr) file and exit the program. 
//  For most applications, replace this function with one 
//  that does more extensive error reporting.

void MyHandleError(LPTSTR psz, int nErrorNumber)
{
	_ftprintf(stderr, TEXT("An error occurred in the program. \n"));
	_ftprintf(stderr, TEXT("%s\n"), psz);
	_ftprintf(stderr, TEXT("Error number %x.\n"), nErrorNumber);
}