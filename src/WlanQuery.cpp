#ifndef UNICODE
#define UNICODE
#endif
#ifndef  _WIN32_WINNT
#define  _WIN32_WINNT _WIN32_WINNT_WINXP
#endif

#pragma comment(lib, "version.lib")
// Need to link with Wlanapi.lib and Ole32.lib
//XP x64 SP2 did not have wlanapi.dll in system32? why?
#pragma comment(lib, "wlanapi.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "Wininet.lib")

#include <iostream>

//#include "GlobalFunctions.h"
#include <atlstr.h>

#include <windows.h>
#include <wlanapi.h>
#include <Windot11.h>           // for DOT11_SSID struct
#include <objbase.h>
#include <wtypes.h>
#include <string>
#include <atlbase.h>

#include <stdio.h>
#include <stdlib.h>

#include <WinInet.h>
using namespace std;

BOOL bWait = true;
BOOL bIsWindowsVistaorLater;

//OID createfile handle
HANDLE hClientHandle;
TCHAR CurrentMACAddressStr[256]; 

//WinINet
BOOL checkUpdate()
{
	DWORD nErrorNo;
	HINTERNET hOpen, hURLFile;
	LPCWSTR NameProgram = L"WlanQuery";             //      LPCWSTR == Long Pointer to Const Wide String 
	LPCWSTR Website = L"https://github.com/coolshou/WlanQuery/releases/latest";
	//CString MyHttpServer=L"";
	hOpen = InternetOpen(NameProgram, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0 );
	if ( !hOpen) {
		nErrorNo = GetLastError(); // 得到錯誤代碼
		LPSTR lpBuffer;    
		FormatMessage ( FORMAT_MESSAGE_ALLOCATE_BUFFER  |
		    FORMAT_MESSAGE_IGNORE_INSERTS  |
			FORMAT_MESSAGE_FROM_SYSTEM,
			NULL,
			nErrorNo, // 此乃錯誤代碼，通常在程序中可由 GetLastError()得之
			LANG_NEUTRAL,
			(LPTSTR) & lpBuffer,
			0 ,
			NULL );
		//cerr << "Error in opening internet" << endl;
		wprintf(L"Error in opening internet: %s\n", lpBuffer);
		InternetCloseHandle(hOpen);
		//  Free the buffer.
		LocalFree (lpBuffer);
		return false;
    }
	//https://msdn.microsoft.com/en-us/library/windows/desktop/aa385098%28v=vs.85%29.aspx
	hURLFile = InternetOpenUrl( 
		hOpen, 								//The handle to the current Internet session. The handle must have been returned by a previous call to InternetOpen.
		Website, 							//A pointer to a null-terminated string variable that specifies the URL to begin reading. Only URLs beginning with ftp:, http:, https: are supported.	
		NULL, 								//A pointer to a null-terminated string that specifies the headers to be sent to the HTTP server
		NULL, 								//The size of the additional headers, in TCHARs
		INTERNET_FLAG_SECURE | 				//flag: SSL,
		INTERNET_FLAG_RELOAD | INTERNET_FLAG_DONT_CACHE,	// RELOAD, NO CACHE
		NULL 								//A pointer to a variable that specifies the application-defined value that is passed, along with the returned handle, to any callback functions.
	);            //Need to open the URL    
	if(!hURLFile) {
		//TODO: error on network can not access
		nErrorNo = GetLastError(); // 得到錯誤代碼
		if(nErrorNo!=0)
		{
			if(nErrorNo==ERROR_INTERNET_EXTENDED_ERROR)
			{
				wstring wstrBuffer;
				DWORD bufferLength;
				InternetGetLastResponseInfo(&nErrorNo,NULL,&bufferLength);
				wstrBuffer.resize( bufferLength + 1 );
				InternetGetLastResponseInfo(&nErrorNo,&wstrBuffer[0],&bufferLength);
			} else {
				LPSTR lpBuffer; 
				FormatMessage ( FORMAT_MESSAGE_ALLOCATE_BUFFER  |
					FORMAT_MESSAGE_IGNORE_INSERTS  |
					FORMAT_MESSAGE_FROM_SYSTEM,
					NULL,
					nErrorNo, // 此乃錯誤代碼，通常在程序中可由 GetLastError()得之
					LANG_NEUTRAL,
					(LPTSTR) & lpBuffer,
					0 ,
					NULL );
				wprintf(L"Error in opening Website: %s\n %s\n", Website, lpBuffer);
				LocalFree (lpBuffer);
			}
			
		}
		InternetCloseHandle(hURLFile);
		InternetCloseHandle(hOpen);
		//  Free the buffer.

		return false;
	}
	//TODO: buffer size handle?
	/* output is ?????
	//Pointer to dynamic buffer.
    //char *data = 0;
    //Dynamic data size.
	DWORD dwBytesRead = 0 ;
    //DWORD dataSize = 0;
	std::string output;
	do {
		char buffer[2000];
        InternetReadFile(hURLFile, (LPVOID) buffer, _countof(buffer), &dwBytesRead);
        //Allocate more space.
        //char *tempData = new char[dataSize + dwBytesRead];
        //Copy the already-fetched data into the new buffer.
        //memcpy(tempData, data, dataSize);
        //Now copy the new chunk of data.
        //memcpy(tempData + dataSize, buffer, dwBytesRead);
        //Now update the permanent variables
        //delete[] data;
        //data = tempData;
        //dataSize += dwBytesRead;
		output.append(buffer, dwBytesRead);
	} while (dwBytesRead);
	//TODO: parser data
	wprintf(L"TODO: parser data: %s\n", output);
	*/
	//dump content to file 
	
	DWORD dwBytesRead;
    VOID * szTemp[25];
	FILE * pFile ;
	CHAR *szFileName = "tmp.html";
	if  ( !(pFile = fopen (szFileName, "wb" ) ) )
	{
		cerr << "Error !" << endl;
		return FALSE;
	}
	do {
		// Keep coping in 25 bytes chunks, while file has any data left.
        // Note: bigger buffer will greatly improve performance.
        if (!InternetReadFile (hURLFile, szTemp, 100,  &dwBytesRead) )
        {
            fclose (pFile);
            cerr << "Error !" << endl;
			return FALSE;
        }
        if (!dwBytesRead)
            break;  // Condition of dwSize=0 indicate EOF. Stop.
        else
            fwrite(szTemp, sizeof (char), dwBytesRead , pFile);
	}while (TRUE);
	fflush (pFile);
    fclose (pFile);
	
	//end file

	/*
	InternetReadFile(hURLFile, fileBuffer, 100, &dwBytesRead);
	while (dwBytesRead == 100)
	{
		InternetReadFile(hURLFile, fileBuffer, 100, &dwBytesRead);
		fileBuffer[dwBytesRead] = '\0';
		cout << fileBuffer;
	}
	*/
	cout << endl;
	InternetCloseHandle(hURLFile);
	InternetCloseHandle(hOpen);
	return true;

}

/*get file*/
/*
inet_service = create inet
data = create u_inetresult
inet_service.geturl("http://test.com/a.pdf",data)

li_fln = FileOpen(as_FileName, StreamMode!, Write!, LockReadWrite!,
Replace!)
If li_fln < 0 Then Return -1 // Can't Open File to Modify

ll_StrLen = Len(data)

If ll_StrLen > 32765 Then
 If Mod(ll_StrLen, 32765) = 0 Then
  li_return = ll_StrLen / 32765
 Else
  li_return = (ll_StrLen / 32765) + 1
 End if
Else
 li_return = 1
End if

ll_CurrentPos = 1

For li_Cnt = 1 To li_return
 ls_record = Mid(ls_file, ll_CurrentPos, 32765)
 ll_CurrentPos += 32765
 If FileWrite(li_fln, ls_record) = -1 Then
  Return // Can't write
 End if
Next

FileClose(li_fln)
*/
CString getVersion()
{
	/*
	CString current_version(_T(""));
	current_version = CGlobalFunctions::GetFileVersionX();
	/*
	wprintf( L"FileVersion: %s\nProductVersion: %s\nMyPrivateInfo: %s", 
             CGlobalFunctions::GetFileVersionX(), 
             CGlobalFunctions::GetProductVersionX(),
             CGlobalFunctions::GetVersionInfo(NULL, "MyPrivateInfo"));
			*/
	return "0";
} 

BOOL checkVistaAbove()
{
	OSVERSIONINFO osvi;
    BOOL bIsWindowsXPorLater;

    ZeroMemory(&osvi, sizeof(OSVERSIONINFO));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);

    GetVersionEx(&osvi);

    bIsWindowsVistaorLater = 
       ( (osvi.dwMajorVersion > 6) ||
       ( (osvi.dwMajorVersion == 6) && (osvi.dwMinorVersion >= 0) ));
       
    return true;
}

/*
//TODO
ULONG getChannel(HANDLE *hClient, const GUID *pInterfaceGuid) 
{
	DWORD dwResult = 0;
	ULONG dwRetVal = 0;
	
	DWORD channelSize= sizeof(ULONG);
	ULONG channel=0;
	WLAN_OPCODE_VALUE_TYPE opCode = wlan_opcode_value_type_query_only;
	
	dwResult = WlanQueryInterface(hClient,
								  pInterfaceGuid,
								  wlan_intf_opcode_channel_number,
								  NULL,
								  &channelSize,
								  (PVOID *) &channel, 
								  &opCode);

	if (dwResult != ERROR_SUCCESS) {
		wprintf(L"    WlanQueryInterface channel failed with error: %u\n", dwResult);
		dwRetVal = 0;
		// You can use FormatMessage to find out why the function failed
	} else {
		wprintf(L"    channel:", channel);
		dwRetVal = channel;
	}
	return dwRetVal;
}
*/
//TODO
ULONG getRSSI(HANDLE* hClient, const GUID *pInterfaceGuid) 
{
	DWORD dwResult = 0;
	ULONG dwRetVal = 0;
	
	DWORD rssiSize= sizeof(ULONG);
	ULONG rssi=0;
	WLAN_OPCODE_VALUE_TYPE opCode = wlan_opcode_value_type_query_only;
	
	dwResult = WlanQueryInterface(hClient,
								  pInterfaceGuid,
								  wlan_intf_opcode_rssi,
								  NULL,
								  &rssiSize,
								  (PVOID *) &rssi, 
								  &opCode);

	if (dwResult != ERROR_SUCCESS) {
		wprintf(L"    WlanQueryInterface rssi failed with error: %u\n", dwResult);
		dwRetVal = 0;
		// You can use FormatMessage to find out why the function failed
	} else {
		wprintf(L"    rssi:", rssi);
		dwRetVal = rssi;
	}
	return dwRetVal;
}

//convert frequency to channel
USHORT freqToChannel(ULONG freq)
{
	USHORT ch;
	ch =0;
	//TODO: 60GHz
	if (freq > 5000000) {
		//5GHz
		ch = ((freq - 5150000)/1000)/5 + 30;
	} else {
		//2.4GHz
		ch = ((freq - 2412000)/1000)/5 + 1;
	}
	return ch;
}

/**
* Show the connected AP info using the NDIS 802.11 IOCTLs.
*/
INT ShowConnectedAPwithNDIS(WCHAR* wsNICGUIDinString )
{
	INT	rtn;
	//TCHAR szCurrentESSID[256];
	//WCHAR szCurrentESSID[256];
	TCHAR szCurrentMACAddressStr[256]; 
	INT iCurrentRSSI;
	INT iCurrentLinkQuality;
	NDIS_802_11_RSSI ndisRSSI;
	NDIS_802_11_SSID ndisESSID;
	NDIS_802_11_MAC_ADDRESS ndisMACAddress;
//	WCHAR	wsNICGUIDinString[256];
	char	sNICIDFullPath[256];
	DWORD	dwMemSize;
	ULONG	ulBytesReturned;
	ULONG	ulOIDCode;

	// open handle
	memset(sNICIDFullPath, 0, 256);				
	sprintf_s(sNICIDFullPath, "\\\\.\\%S", wsNICGUIDinString);
	hClientHandle = CreateFileA(sNICIDFullPath, GENERIC_READ | GENERIC_WRITE, 
											FILE_SHARE_READ | FILE_SHARE_WRITE,
											NULL, OPEN_EXISTING,
											0, NULL) ;

	if(hClientHandle == INVALID_HANDLE_VALUE)
	{
		wprintf(L"Error in CreateFileA\n");
		return 0;
	}

	// call to get connected ESSID
	dwMemSize = sizeof(NDIS_802_11_SSID);
	ulOIDCode = OID_802_11_SSID;
	ulBytesReturned = 0;
	rtn = DeviceIoControl(hClientHandle, IOCTL_NDIS_QUERY_GLOBAL_STATS,
							&ulOIDCode, sizeof(ulOIDCode), (ULONG *) &ndisESSID,
							dwMemSize, &ulBytesReturned, NULL);
	/*
看起來很好使用，但是注意的是 IOCTL_NDIS_QUERY_GLOBAL_STATS 只是適合查詢(Query)，估計是出於安全的考慮，
微軟沒有允許Set OID，因為這樣會更改到底層驅動的某些屬性。
當然Vista開始，你可以使用與某個OID對應的WMI,比如對於 OID_802_11_BSSID_LIST_SCAN 你可以使用 WlanScan 函數，
當然也有對應的 Ndis6.0 版本的 OID_DOT11_SCAN_REQUEST
但是是不是可以在User Mode層使用這個OID，未可知。但是 WlanScan 是可以的。
	*/
	
	if(rtn == 0)
	{
		wprintf(L"Error in DeviceIoControl\n");
		CloseHandle(hClientHandle);
		return rtn;
	}
	//memset(szCurrentESSID, 0, 256);
	//memcpy(szCurrentESSID, ndisESSID.Ssid, ndisESSID.SsidLength);


	// call to get connected MAC Address
	dwMemSize = sizeof(NDIS_802_11_MAC_ADDRESS);
	ulOIDCode = OID_802_11_BSSID;
	ulBytesReturned = 0;
	rtn = DeviceIoControl(hClientHandle, IOCTL_NDIS_QUERY_GLOBAL_STATS,
							&ulOIDCode, sizeof(ulOIDCode), (ULONG *) &ndisMACAddress,
							dwMemSize, &ulBytesReturned, NULL);
	if(rtn == 0)
	{
		wprintf(L"Error in DeviceIoControl\n");
		CloseHandle(hClientHandle);
		return rtn;
	}
	memset(szCurrentMACAddressStr, 0, 256);
	_stprintf_s(szCurrentMACAddressStr, 256, L"%02x:%02x:%02x:%02x:%02x:%02x", 
		ndisMACAddress[0],
		ndisMACAddress[1],
		ndisMACAddress[2],
		ndisMACAddress[3],
		ndisMACAddress[4],
		ndisMACAddress[5]);
	//global
	memset(CurrentMACAddressStr, 0, 256);
	_stprintf_s(CurrentMACAddressStr, 256, L"%02x:%02x:%02x:%02x:%02x:%02x", 
		ndisMACAddress[0],
		ndisMACAddress[1],
		ndisMACAddress[2],
		ndisMACAddress[3],
		ndisMACAddress[4],
		ndisMACAddress[5]);	
		
	// call to get RSSI
	ndisRSSI = 0;
	dwMemSize = sizeof(NDIS_802_11_RSSI);
	ulOIDCode = OID_802_11_RSSI;
	ulBytesReturned = 0;
	rtn = DeviceIoControl(hClientHandle, IOCTL_NDIS_QUERY_GLOBAL_STATS,
							&ulOIDCode, sizeof(ulOIDCode), (ULONG *) &ndisRSSI,
							dwMemSize, &ulBytesReturned, NULL);
	if(rtn == 0)
	{
		wprintf(L"Error in DeviceIoControl\n");
		CloseHandle(hClientHandle);
		return rtn;
	}

	// close handle
	CloseHandle(hClientHandle);

	iCurrentRSSI = ndisRSSI;
	// MS computes link quality as follows;  
	// range 1 to 100, maps rssi from -100 to -50, linear interpolation
	iCurrentLinkQuality = (ndisRSSI + 100) * 2;
	if(iCurrentLinkQuality < 0)
	{
		iCurrentLinkQuality = 0;
	}
	else if(iCurrentLinkQuality > 100)
	{
		iCurrentLinkQuality = 100;
	}

	//wprintf(L"Network Name (Profile Name): %s\n", szCurrentESSID);
	wprintf(L"    AP MAC Address : %s\t\t \n", szCurrentMACAddressStr);
	wprintf(L"    RSSI           : %d\t\t \n", iCurrentRSSI);
	wprintf(L"    Link Quality   : %d\t\t \n", iCurrentLinkQuality);
	//channel 
	
	//_tprintf("\n\n");
	//_tprintf("Type 99 to continue ... ");
	//_tscanf_s("%d", &iContinue);

	return rtn;
}

VOID WlanNotification(WLAN_NOTIFICATION_DATA *wlanNotifData,VOID *p)
{
	if(wlanNotifData->NotificationCode == wlan_notification_acm_scan_complete)
	{
	    bWait = false;
	}
	else if(wlanNotifData->NotificationCode == wlan_notification_acm_scan_fail)
	{
	    printf("Scanning failed with error: %x\n", wlanNotifData->pData);
	    bWait = false;
	}
}

void CALLBACK TimerProc(HWND hWnd,UINT nMsg,UINT nTimerid,DWORD dwTime) 
{
	printf("TimerProc\n");
	bWait = false;
}

int wmain()
{
    // Declare and initialize variables.
    HANDLE hClient = NULL;
    //WLAN API Client version for Windows Vista and Windows Server 2008
    //1: for Client version for Windows XP with SP3 and Wireless LAN API for Windows XP with SP2.
    DWORD dwMaxClient = 2;
    //The version of the WLAN API that will be used in this session
    DWORD dwCurVersion = 0;
    DWORD dwResult = 0;
    DWORD dwRetVal = 0;
    int iRet = 0;
	TCHAR MACAddressStr[256]; 
    bool bIsCurrentConnected = false;
    WCHAR GuidString[39] = { 0 };
    unsigned int i, j, k, l, r;
    
    WLAN_RATE_SET rateSet;
    USHORT rate_in_mbps;
	USHORT maxRate_in_mbps = 0;
    // variables used for WlanEnumInterfaces
    PWLAN_INTERFACE_INFO_LIST pIfList = NULL;
    PWLAN_INTERFACE_INFO pIfInfo = NULL;

	PWLAN_AVAILABLE_NETWORK_LIST pNetworkList = NULL;
	PWLAN_AVAILABLE_NETWORK pNetworkEntry = NULL;

	PWLAN_BSS_LIST		pBssList = NULL;
	PWLAN_BSS_ENTRY		pBssEntry = NULL;

    // variables used for WlanQueryInterfaces for opcode = wlan_intf_opcode_current_connection
    PWLAN_CONNECTION_ATTRIBUTES pConnectInfo = NULL;
    DWORD connectInfoSize = sizeof(WLAN_CONNECTION_ATTRIBUTES);
    WLAN_OPCODE_VALUE_TYPE opCode = wlan_opcode_value_type_invalid;

    dwResult = WlanOpenHandle(dwMaxClient, NULL, &dwCurVersion, &hClient);
    if (dwResult != ERROR_SUCCESS) {
        wprintf(L"WlanOpenHandle failed with error: %u\n", dwResult);
        return 1;
        // You can use FormatMessage here to find out why the function failed
    }
	checkVistaAbove();
	//TODO: use arg -c to check Update
	//checkUpdate();
	getVersion();

    dwResult = WlanEnumInterfaces(hClient, NULL, &pIfList);
    if (dwResult != ERROR_SUCCESS) {
        wprintf(L"WlanEnumInterfaces failed with error: %u\n", dwResult);
        return 1;
        // You can use FormatMessage here to find out why the function failed
    } else {
        wprintf(L"Num Entries: %lu\n", pIfList->dwNumberOfItems);
        wprintf(L"Current Index: %lu\n", pIfList->dwIndex);
        for (i = 0; i < (int) pIfList->dwNumberOfItems; i++) {
            pIfInfo = (WLAN_INTERFACE_INFO *) & pIfList->InterfaceInfo[i];
            wprintf(L"  Interface Index[%u]:\t %lu\n", i, i);
            iRet =
                StringFromGUID2(pIfInfo->InterfaceGuid, (LPOLESTR) & GuidString,
                                sizeof (GuidString) / sizeof (*GuidString));
            // For c rather than C++ source code, the above line needs to be
            // iRet = StringFromGUID2(&pIfInfo->InterfaceGuid, (LPOLESTR) &GuidString, 
            //     sizeof(GuidString)/sizeof(*GuidString)); 
            if (iRet == 0)
                wprintf(L"StringFromGUID2 failed\n");
            else {
                wprintf(L"  InterfaceGUID[%d]:\t %ws\n", i, GuidString);
            }
            wprintf(L"  Interface Description[%d]: %ws", i, pIfInfo->strInterfaceDescription);
            wprintf(L"\n");
            wprintf(L"  Interface State[%d]:\t ", i);
            switch (pIfInfo->isState) {
            case wlan_interface_state_not_ready:
                wprintf(L"Not ready\n");
                break;
            case wlan_interface_state_connected:
                wprintf(L"Connected\n");
                break;
            case wlan_interface_state_ad_hoc_network_formed:
                wprintf(L"First node in a ad hoc network\n");
                break;
            case wlan_interface_state_disconnecting:
                wprintf(L"Disconnecting\n");
                break;
            case wlan_interface_state_disconnected:
                wprintf(L"Not connected\n");
                break;
            case wlan_interface_state_associating:
                wprintf(L"Attempting to associate with a network\n");
                break;
            case wlan_interface_state_discovering:
                wprintf(L"Auto configuration is discovering settings for the network\n");
                break;
            case wlan_interface_state_authenticating:
                wprintf(L"In process of authenticating\n");
                break;
            default:
                wprintf(L"Unknown state %ld\n", pIfInfo->isState);
                break;
            }
            wprintf(L"\n");
			
            // If interface state is connected, call WlanQueryInterface
            // to get current connection attributes
            if (pIfInfo->isState == wlan_interface_state_connected) {
                dwResult = WlanQueryInterface(hClient,
                                              &pIfInfo->InterfaceGuid,
                                              wlan_intf_opcode_current_connection,
                                              NULL,
                                              &connectInfoSize,
                                              (PVOID *) &pConnectInfo, 
                                              &opCode);

                if (dwResult != ERROR_SUCCESS) {
                    wprintf(L"WlanQueryInterface WLAN_CONNECTION_ATTRIBUTES failed with error: %u\n", dwResult);
                    dwRetVal = 1;
                    // You can use FormatMessage to find out why the function failed
                } else {
                    wprintf(L"  WLAN_CONNECTION_ATTRIBUTES for this interface\n");

                    wprintf(L"  Interface State:\t ");
                    switch (pConnectInfo->isState) {
                    case wlan_interface_state_not_ready:
                        wprintf(L"Not ready\n");
                        break;
                    case wlan_interface_state_connected:
                        wprintf(L"Connected\n");
                        break;
                    case wlan_interface_state_ad_hoc_network_formed:
                        wprintf(L"First node in a ad hoc network\n");
                        break;
                    case wlan_interface_state_disconnecting:
                        wprintf(L"Disconnecting\n");
                        break;
                    case wlan_interface_state_disconnected:
                        wprintf(L"Not connected\n");
                        break;
                    case wlan_interface_state_associating:
                        wprintf(L"Attempting to associate with a network\n");
                        break;
                    case wlan_interface_state_discovering:
                        wprintf
                            (L"Auto configuration is discovering settings for the network\n");
                        break;
                    case wlan_interface_state_authenticating:
                        wprintf(L"In process of authenticating\n");
                        break;
                    default:
                        wprintf(L"Unknown state %ld\n", pIfInfo->isState);
                        break;
                    }

                    wprintf(L"  Connection Mode:\t ");
                    switch (pConnectInfo->wlanConnectionMode) {
                    case wlan_connection_mode_profile:
                        wprintf(L"A profile is used to make the connection\n");
                        break;
                    case wlan_connection_mode_temporary_profile:
                        wprintf(L"A temporary profile is used to make the connection\n");
                        break;
                    case wlan_connection_mode_discovery_secure:
                        wprintf(L"Secure discovery is used to make the connection\n");
                        break;
                    case wlan_connection_mode_discovery_unsecure:
                        wprintf(L"Unsecure discovery is used to make the connection\n");
                        break;
                    case wlan_connection_mode_auto:
                        wprintf
                            (L"connection initiated by wireless service automatically using a persistent profile\n");
                        break;
                    case wlan_connection_mode_invalid:
                        wprintf(L"Invalid connection mode\n");
                        break;
                    default:
                        wprintf(L"Unknown connection mode %ld\n",
                                pConnectInfo->wlanConnectionMode);
                        break;
                    }

                    wprintf(L"  Profile name used:\t %ws\n", pConnectInfo->strProfileName);

                    wprintf(L"  Association Attributes for this connection\n");
                    wprintf(L"    SSID:\t\t ");
                    if (pConnectInfo->wlanAssociationAttributes.dot11Ssid.uSSIDLength == 0)
                        wprintf(L"\n");
                    else {
                        for (k = 0;
                             k < pConnectInfo->wlanAssociationAttributes.dot11Ssid.uSSIDLength;
                             k++) {
                            wprintf(L"%c",
                                    (int) pConnectInfo->wlanAssociationAttributes.dot11Ssid.ucSSID[k]);
                        }
                        wprintf(L"\n");
                    }

                    wprintf(L"    BSS Network type:\t ");
                    switch (pConnectInfo->wlanAssociationAttributes.dot11BssType) {
                    case dot11_BSS_type_infrastructure:
                        wprintf(L"Infrastructure\n");
                        break;
                    case dot11_BSS_type_independent:
                        wprintf(L"independent BSS\n");
                        break;
						default:
                        wprintf(L"Other = %lu\n",
                                pConnectInfo->wlanAssociationAttributes.dot11BssType);
                        break;
                    }
					if (!bIsWindowsVistaorLater) {
						ShowConnectedAPwithNDIS((LPOLESTR)&GuidString);
					} else {
						wprintf(L"    AP MAC address:\t ");
						//global
						memset(CurrentMACAddressStr, 0, 256);
						_stprintf_s(CurrentMACAddressStr, 256, L"%02x:%02x:%02x:%02x:%02x:%02x", 
							pConnectInfo->wlanAssociationAttributes.dot11Bssid[0],
							pConnectInfo->wlanAssociationAttributes.dot11Bssid[1],
							pConnectInfo->wlanAssociationAttributes.dot11Bssid[2],
							pConnectInfo->wlanAssociationAttributes.dot11Bssid[3],
							pConnectInfo->wlanAssociationAttributes.dot11Bssid[4],
							pConnectInfo->wlanAssociationAttributes.dot11Bssid[5]);	
						wprintf(L"%s\n", CurrentMACAddressStr);							

						//following Available in Windows Vista and later
						wprintf(L"    PHY network type:\t ");
						switch (pConnectInfo->wlanAssociationAttributes.dot11PhyType) {
						case dot11_phy_type_unknown:
							wprintf(L"Unknown");
							break;
						case dot11_phy_type_fhss:
							wprintf(L"Frequency-hopping spread-spectrum (FHSS)\n");
							break;
						case dot11_phy_type_dsss:
							wprintf(L"Direct sequence spread spectrum (DSSS)\n");
							break;
						case dot11_phy_type_irbaseband:
							wprintf(L"Infrared (IR) baseband\n");
							break;
						case dot11_phy_type_ofdm:
							wprintf(L"Orthogonal frequency division multiplexing (OFDM)\n");
							break;
						case dot11_phy_type_hrdsss:
							wprintf(L"High-rate DSSS (HRDSSS) = \n");
							break;
						case dot11_phy_type_erp:
							wprintf(L"Extended rate PHY type\n");
							break;
						case dot11_phy_type_ht:
							wprintf(L"802.11n PHY type\n");
							break;
						case 8: //sdk8.1 dot11_phy_type_vht:
							wprintf(L"802.11ac PHY type\n");
							break;
						case dot11_phy_type_IHV_start:
							wprintf(L"The start of the range independent hardware vendor (IHV)\n");
							break;
						case dot11_phy_type_IHV_end:
							wprintf(L"The end of the range independent hardware vendor (IHV)\n");
							break;
						default:
							wprintf(L"Unknown = %lu\n",
									pConnectInfo->wlanAssociationAttributes.dot11PhyType);
							break;
						}

						wprintf(L"    PHY index:\t\t %u\n",
								pConnectInfo->wlanAssociationAttributes.uDot11PhyIndex);
						//TODO: RSSI
						getRSSI(&hClient,&pIfInfo->InterfaceGuid);

						wprintf(L"    Signal Quality:\t %d\n",
								pConnectInfo->wlanAssociationAttributes.wlanSignalQuality);

						wprintf(L"    Receiving Rate:\t %ld\n",
								pConnectInfo->wlanAssociationAttributes.ulRxRate);

						wprintf(L"    Transmission Rate:\t %ld\n",
								pConnectInfo->wlanAssociationAttributes.ulTxRate);
						//TODO: channel
						//getChannel(hClient,&pIfInfo->InterfaceGuid);
						wprintf(L"\n");
					}
                    
                    wprintf(L"  Security Attributes for this connection\n");

                    wprintf(L"    Security enabled:\t ");
                    if (pConnectInfo->wlanSecurityAttributes.bSecurityEnabled == 0)
                        wprintf(L"No\n");
                    else
                        wprintf(L"Yes\n");

                    wprintf(L"    802.1X enabled:\t ");
                    if (pConnectInfo->wlanSecurityAttributes.bOneXEnabled == 0)
                        wprintf(L"No\n");
                    else
                        wprintf(L"Yes\n");

                    wprintf(L"    Authentication Algorithm: ");
                    switch (pConnectInfo->wlanSecurityAttributes.dot11AuthAlgorithm) {
                    case DOT11_AUTH_ALGO_80211_OPEN:
                        wprintf(L"802.11 Open\n");
                        break;
                    case DOT11_AUTH_ALGO_80211_SHARED_KEY:
                        wprintf(L"802.11 Shared\n");
                        break;
                    case DOT11_AUTH_ALGO_WPA:
                        wprintf(L"WPA\n");
                        break;
                    case DOT11_AUTH_ALGO_WPA_PSK:
                        wprintf(L"WPA-PSK\n");
                        break;
                    case DOT11_AUTH_ALGO_WPA_NONE:
                        wprintf(L"WPA-None\n");
                        break;
                    case DOT11_AUTH_ALGO_RSNA:
                        wprintf(L"RSNA\n");
                        break;
                    case DOT11_AUTH_ALGO_RSNA_PSK:
                        wprintf(L"RSNA with PSK\n");
                        break;
                    default:
                        wprintf(L"Other (%lu)\n", pConnectInfo->wlanSecurityAttributes.dot11AuthAlgorithm);
                        break;
                    }
                        
                    wprintf(L"    Cipher Algorithm:\t ");
                    switch (pConnectInfo->wlanSecurityAttributes.dot11CipherAlgorithm) {
                    case DOT11_CIPHER_ALGO_NONE:
                        wprintf(L"None\n");
                        break;
                    case DOT11_CIPHER_ALGO_WEP40:
                        wprintf(L"WEP-40\n");
                        break;
                    case DOT11_CIPHER_ALGO_TKIP:
                        wprintf(L"TKIP\n");
                        break;
                    case DOT11_CIPHER_ALGO_CCMP:
                        wprintf(L"CCMP\n");
                        break;
                    case DOT11_CIPHER_ALGO_WEP104:
                        wprintf(L"WEP-104\n");
                        break;
                    case DOT11_CIPHER_ALGO_WEP:
                        wprintf(L"WEP\n");
                        break;
                    default:
                        wprintf(L"Other (0x%x)\n", pConnectInfo->wlanSecurityAttributes.dot11CipherAlgorithm);
                        break;
                    }
                    wprintf(L"\n");
                }
            }
			//scan first
			//test? passible cause disconnect?
			if (1) {
				DWORD dwPrevNotif = 0;
				// Scan takes awhile so we need to register a callback
				//Windows XP with SP3 and Wireless LAN API for Windows XP with SP2:  Only the wlan_notification_acm_connection_complete and wlan_notification_acm_disconnected notifications are available.
				if(dwResult = WlanRegisterNotification(hClient, WLAN_NOTIFICATION_SOURCE_ACM, TRUE,
				  (WLAN_NOTIFICATION_CALLBACK)WlanNotification, NULL, NULL, &dwPrevNotif) != ERROR_SUCCESS) {
					throw("[x] Unable to register for notifications");
				}
	 
				printf("[%d] Scanning for nearby networks...\n", i);
				//The WlanScan function returns immediately and does not provide a notification when the scan is complete on Windows XP with SP3 or the Wireless LAN API for Windows XP with SP2. (timeout after 4sec)
				//TODO: does WlanScan (OID_802_11_BSSID_LIST_SCAN) is 
				//This list includes BSSIDs for all BSSs responding on frequency channels that are permitted in the region in which the device is operating. The driver will return the contents of this list when queried by OID_802_11_BSSID_LIST.
				//use OID_DOT11_SCAN_REQUEST
				if(dwResult = WlanScan(hClient, &pIfInfo->InterfaceGuid, NULL, NULL, NULL) != ERROR_SUCCESS) {
					throw("[x] Scan failed, check adapter is enabled");
				}
				// 
				UINT nRet;
				MSG msg;
				if (! bIsWindowsVistaorLater) {
					printf("XP and below no support wlan_notification_acm_scan_complete\n");
					//XP just wait 5 sec
					nRet = SetTimer(NULL,0,5000,TimerProc);
				}
				bWait = true;
				while(bWait) {
					Sleep(100);
					wprintf(L".");
					//TODO: following will not let while keep out put "."
					if (! bIsWindowsVistaorLater) {
						//for SetTimer with NULL handle
						GetMessage(&msg, NULL, 0, 0);
						DispatchMessage(&msg);
					}
				}

				wprintf(L"\n");
				// Unregister callback, don't care if it succeeds or not
				WlanRegisterNotification(hClient, WLAN_NOTIFICATION_SOURCE_NONE, TRUE, NULL, NULL, NULL, &dwPrevNotif);
				if (! bIsWindowsVistaorLater) {
					KillTimer(NULL, nRet);
				}
			}
			//WlanGetAvailableNetworkList
			/*TODO: Get profile list for this interface?
			dwResult = WlanGetAvailableNetworkList(hClient,  
                &pIfInfo->InterfaceGuid,  
                0,   
                NULL,   
                &pBssList);  
			if (dwResult != ERROR_SUCCESS) {  
                RETAILMSG(OUTPUT_LOGMSG,(L"WlanGetAvailableNetworkList failed with error: %u\r\n",  
                    dwResult));  
                dwRetVal = 1;  
                // You can use FormatMessage to find out why the function failed   
            } else {
                RETAILMSG(OUTPUT_LOGMSG, (L"WLAN_AVAILABLE_NETWORK_LIST for this interface\r\n"));  
                RETAILMSG(OUTPUT_LOGMSG,(L"Num Entries: %d\r\n", pBssList->dwNumberOfItems));  
  
                for (j = 0; j < pBssList->dwNumberOfItems; j++)   
                {  
                    pBssEntry = (WLAN_AVAILABLE_NETWORK *)&pBssList->Network[j];  
                    RETAILMSG(OUTPUT_LOGMSG,(L"  Profile Name[%u]:  %s\r\n", j, &pBssEntry->strProfileName));  
                    RETAILMSG(OUTPUT_LOGMSG,(L"  SSID[%u]:\t\t ", j));  
                    if (pBssEntry->dot11Ssid.uSSIDLength == 0)  
                        RETAILMSG(OUTPUT_LOGMSG,(L"\r\n"));  
                    else   
                    {   
                        CString str = _T("");  
                        str = pBssEntry->dot11Ssid.ucSSID;  
                      
  
                    RETAILMSG(OUTPUT_LOGMSG,(L"%s\r\n", str));  
                        RETAILMSG(OUTPUT_LOGMSG,(L"%s\r\n", &pBssEntry->dot11Ssid.ucSSID));  
                    }  
  
                    RETAILMSG(OUTPUT_LOGMSG,(L"BSS Network type[%u]:\t ", j));  
                    switch (pBssEntry->dot11BssType)  
                    {  
                    case dot11_BSS_type_infrastructure   :  
                        RETAILMSG(OUTPUT_LOGMSG,(L"Infrastructure (%u)\r\n", pBssEntry->dot11BssType));  
                        break;  
                    case dot11_BSS_type_independent:  
                        RETAILMSG(OUTPUT_LOGMSG,(L"Infrastructure (%u)\r\n", pBssEntry->dot11BssType));  
                        break;  
                    default:  
                        RETAILMSG(OUTPUT_LOGMSG,(L"Other (%lu)\r\n", pBssEntry->dot11BssType));  
                        break;  
                    }  
  
                    RETAILMSG(OUTPUT_LOGMSG,(L"  Number of BSSIDs[%u]:\t %u\r\n", j, pBssEntry->uNumberOfBssids));  
                    RETAILMSG(OUTPUT_LOGMSG,(L"  Connectable[%u]:\t ", j));  
                    if (pBssEntry->bNetworkConnectable)  
                        RETAILMSG(OUTPUT_LOGMSG,(L"Yes\r\n"));  
                    else   
                    {  
                        RETAILMSG(OUTPUT_LOGMSG,(L"No\r\n"));  
                        RETAILMSG(OUTPUT_LOGMSG,(L" Not connectable WLAN_REASON_CODE value[%u]:\t %u\r\n", j,   
                            pBssEntry->wlanNotConnectableReason));  
                    }          
  
                    RETAILMSG(OUTPUT_LOGMSG,(L"Number of PHY types supported[%u]:\t %u\r\n", j, pBssEntry->uNumberOfPhyTypes));  
  
                    if (pBssEntry->wlanSignalQuality == 0)  
                        iRSSI = -100;  
                    else if (pBssEntry->wlanSignalQuality == 100)     
                        iRSSI = -50;  
                    else  
                        iRSSI = -100 + (pBssEntry->wlanSignalQuality/2);      
  
                    RETAILMSG(OUTPUT_LOGMSG,(L"  Signal Quality[%u]:\t %u (RSSI: %i dBm)\r\n", j,   
                        pBssEntry->wlanSignalQuality, iRSSI));  
  
                    RETAILMSG(OUTPUT_LOGMSG,(L"  Security Enabled[%u]:\t ", j));  
                    if (pBssEntry->bSecurityEnabled)  
                        RETAILMSG(OUTPUT_LOGMSG,(L"Yes\r\n"));  
                    else  
                        RETAILMSG(OUTPUT_LOGMSG,(L"No\r\n"));  
                    //身份驗證類型   
                    RETAILMSG(OUTPUT_LOGMSG,(L"  Default AuthAlgorithm[%u]: ", j));  
                    switch (pBssEntry->dot11DefaultAuthAlgorithm)   
                    {  
                    case DOT11_AUTH_ALGO_80211_OPEN:  
                        RETAILMSG(OUTPUT_LOGMSG,(L"802.11 Open (%u)\r\n", pBssEntry->dot11DefaultAuthAlgorithm));  
                        break;  
                    case DOT11_AUTH_ALGO_80211_SHARED_KEY:  
                        RETAILMSG(OUTPUT_LOGMSG,(L"802.11 Shared (%u)\r\n", pBssEntry->dot11DefaultAuthAlgorithm));  
                        break;  
                    case DOT11_AUTH_ALGO_WPA:  
                        RETAILMSG(OUTPUT_LOGMSG,(L"WPA (%u)\r\n", pBssEntry->dot11DefaultAuthAlgorithm));  
                        break;  
                    case DOT11_AUTH_ALGO_WPA_PSK:  
                        RETAILMSG(OUTPUT_LOGMSG,(L"WPA-PSK (%u)\r\n", pBssEntry->dot11DefaultAuthAlgorithm));  
                        break;  
                    case DOT11_AUTH_ALGO_WPA_NONE:  
                        RETAILMSG(OUTPUT_LOGMSG,(L"WPA-None (%u)\r\n", pBssEntry->dot11DefaultAuthAlgorithm));  
                        break;  
                    case DOT11_AUTH_ALGO_RSNA:  
                        RETAILMSG(OUTPUT_LOGMSG,(L"RSNA (%u)\r\n", pBssEntry->dot11DefaultAuthAlgorithm));  
                        break;  
                    case DOT11_AUTH_ALGO_RSNA_PSK:  
                        RETAILMSG(OUTPUT_LOGMSG,(L"RSNA with PSK(%u)\r\n", pBssEntry->dot11DefaultAuthAlgorithm));  
                        break;  
                    default:  
                        RETAILMSG(OUTPUT_LOGMSG,(L"Other (%lu)\r\n", pBssEntry->dot11DefaultAuthAlgorithm));  
                        break;  
                    }  
  
                    //加密類型   
                    RETAILMSG(OUTPUT_LOGMSG,(L"  Default CipherAlgorithm[%u]: ", j));  
                    switch (pBssEntry->dot11DefaultCipherAlgorithm)   
                    {  
                    case DOT11_CIPHER_ALGO_NONE:  
                        RETAILMSG(OUTPUT_LOGMSG,(L"None (0x%x)\r\n", pBssEntry->dot11DefaultCipherAlgorithm));  
                        break;  
                    case DOT11_CIPHER_ALGO_WEP40:  
                        RETAILMSG(OUTPUT_LOGMSG,(L"WEP-40 (0x%x)\r\n", pBssEntry->dot11DefaultCipherAlgorithm));  
                        break;  
                    case DOT11_CIPHER_ALGO_TKIP:  
                        RETAILMSG(OUTPUT_LOGMSG,(L"TKIP (0x%x)\r\n", pBssEntry->dot11DefaultCipherAlgorithm));  
                        break;  
                    case DOT11_CIPHER_ALGO_CCMP:  
                        RETAILMSG(OUTPUT_LOGMSG,(L"CCMP (0x%x)\r\n", pBssEntry->dot11DefaultCipherAlgorithm));  
                        break;  
                    case DOT11_CIPHER_ALGO_WEP104:  
                        RETAILMSG(OUTPUT_LOGMSG,(L"WEP-104 (0x%x)\r\n", pBssEntry->dot11DefaultCipherAlgorithm));  
                        break;  
                    case DOT11_CIPHER_ALGO_WEP:  
                        RETAILMSG(OUTPUT_LOGMSG,(L"WEP (0x%x)\r\n", pBssEntry->dot11DefaultCipherAlgorithm));  
                        break;  
                    default:  
                        RETAILMSG(OUTPUT_LOGMSG,(L"Other (0x%x)\r\n", pBssEntry->dot11DefaultCipherAlgorithm));  
                        break;  
                    }  
  
                    RETAILMSG(OUTPUT_LOGMSG,(L"  Flags[%u]:\t 0x%x", j, pBssEntry->dwFlags));  
                    if (pBssEntry->dwFlags)   
                    {  
                        if (pBssEntry->dwFlags & WLAN_AVAILABLE_NETWORK_CONNECTED)  
                            RETAILMSG(OUTPUT_LOGMSG,(L" - Currently connected"));  
                        if (pBssEntry->dwFlags & WLAN_AVAILABLE_NETWORK_CONNECTED)  
                            RETAILMSG(OUTPUT_LOGMSG,(L" - Has profile"));  
                    }     
                    RETAILMSG(OUTPUT_LOGMSG,(L"\r\n"));  
  
                    RETAILMSG(OUTPUT_LOGMSG,(L"\r\n"));  
				}//for (j = 0; j < pBssList->dwNumberOfItems; j++)   
			*/
            //WlanGetNetworkBssList, Vista above
			char *pReserved=NULL;
			DOT11_BSS_TYPE dot11BssType = dot11_BSS_type_any;

			dwResult = WlanGetNetworkBssList(hClient,
				&pIfInfo->InterfaceGuid,
				NULL,
				dot11BssType,
				NULL,
				pReserved, 
				&pBssList);

			if (dwResult != ERROR_SUCCESS) {
				wprintf(L"WlanGetNetworkBssList failed with error: %u\n",
						dwResult);
				dwRetVal = 1;
				// You can use FormatMessage to find out why the function failed
			} else {
				wprintf(L"PWLAN_BSS_LIST for this interface\n");
				wprintf(L" %32ls  %16ls %4ls %ls %ls %ls\n",L"SSID",L"MAC",L"RSSI",L"RATE",L"TYPE",L"FREQUENCY");
				
				string result_ssid;
				string result_mac;
				
				for (j = 0; j < pBssList->dwNumberOfItems; j++) {
					bIsCurrentConnected = false;
					pBssEntry =
						(WLAN_BSS_ENTRY *) & pBssList->wlanBssEntries[j];
					//ssid
					//add empty char at begin of ssid
					for (l = 0; l<=(32-pBssEntry->dot11Ssid.uSSIDLength);l++) {
						wprintf(L"%c", 0x20);
					}
					for (k = 0; k < pBssEntry->dot11Ssid.uSSIDLength; k++) {
                        wprintf(L"%c", (int) pBssEntry->dot11Ssid.ucSSID[k]);
                    }
                    wprintf(L" ");
					//mac
					memset(MACAddressStr, 0, 256);
					_stprintf_s(MACAddressStr, 256, L"%02x:%02x:%02x:%02x:%02x:%02x", 
						pBssEntry->dot11Bssid[0], pBssEntry->dot11Bssid[1],
						pBssEntry->dot11Bssid[2], pBssEntry->dot11Bssid[3],
						pBssEntry->dot11Bssid[4], pBssEntry->dot11Bssid[5]);	
					wprintf(L"%s ", MACAddressStr);
					
					//rssi
					wprintf(L"%4ld ", pBssEntry->lRssi);
					//rate
					rateSet = pBssEntry->wlanRateSet;
					maxRate_in_mbps =0;
					for (r = 0; r < rateSet.uRateSetLength ;r++) {
						//Mbps
						//basic rate
						rate_in_mbps = (rateSet.usRateSet[r] & 0x7FFF) * 0.5;
						if (rate_in_mbps > maxRate_in_mbps) {
							maxRate_in_mbps =rate_in_mbps;
						}
					}
					wprintf(L"%4ld ", maxRate_in_mbps);
					//type
					switch (pBssEntry->dot11BssPhyType) {
					case dot11_phy_type_ofdm:
						wprintf(L"%ls  ", L"11a");
						break;
					case dot11_phy_type_hrdsss:
						wprintf(L"%ls  ", L"11b");					
						break;
					case dot11_phy_type_erp:
						wprintf(L"%ls  ", L"11g");
						break;
					case dot11_phy_type_ht:
						wprintf(L"%ls  ", L"11n");
						break;
					case 8://11ac vht, sdk8.1, dot11_phy_type_vht
						wprintf(L"%ls  ", L"11ac");
						break;
					default:
						wprintf(L"%ls(%d)", L"N/A", pBssEntry->dot11BssPhyType);
						break;
					}
					//channel
					wprintf(L"%4ld (%d)", (pBssEntry->ulChCenterFrequency)/1000, freqToChannel(pBssEntry->ulChCenterFrequency));
					//current connected 
					if (!_tcscmp(MACAddressStr, CurrentMACAddressStr)) {
						wprintf(L" *");
					}
					wprintf(L"\n");
				}
				wprintf(L"*Num Entries: %lu\n", pBssList->dwNumberOfItems);
			}
			//TODO
			/*
			if (pBssList != NULL) {
				WlanFreeMemory(pBssList);
				pBssList = NULL;
			}
			*/
        }
    }
    if (pConnectInfo != NULL) {
        WlanFreeMemory(pConnectInfo);
        pConnectInfo = NULL;
    }

    if (pIfList != NULL) {
        WlanFreeMemory(pIfList);
        pIfList = NULL;
    }

    return dwRetVal;
}
