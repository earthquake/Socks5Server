// Socks5Server.cpp : Defines the entry point for the console application.
//
#include "stdafx.h"
#include <windows.h>
#include "SocksServer.h"

int main()
{
	StartServer(L"127.0.0.1", L"1080");

    return 0;
}

