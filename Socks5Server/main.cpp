// Socks5Server.cpp : Defines the entry point for the console application.
//
#include "stdafx.h"
#include <windows.h>
#include "SocksServer.h"

int wmain(int argc, wchar_t* argv[])
{
	if (argc < 3)
	{
		wprintf(L"Usage : .\\%s [Listening IP] [Listening Port]\r\n\r\n", argv[0]);
		StartServer(L"127.0.0.1", L"1080");
	}
	else
	{
		StartServer(argv[1], argv[2]);
	}
	

    return 0;
}

