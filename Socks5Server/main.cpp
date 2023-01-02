// Socks5Server.cpp : Defines the entry point for the console application.
//
#include "stdafx.h"
#include <windows.h>
#include "SocksServer.h"

static wchar_t* charToWChar(const char* text)
{
    const size_t size = strlen(text) + 1;
    wchar_t* wText = new wchar_t[size];
    swprintf(wText, size, L"%hs", text);
    return wText;
}

int main(int argc, char ** argv)
{
    if (argc < 3) printf("Usage : .\\Socks5Server [Listening IP] [Listening Port]");
	else StartServer(charToWChar(argv[1]), charToWChar(argv[2]));

    return 0;
}
