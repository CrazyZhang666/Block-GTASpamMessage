#include "pch.h"
#include "minhook/minhook.h"
#include "sigscan.h"

#include <iostream>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <codecvt>

using namespace std;

bool g_running = true;

std::vector<string> words;

std::string UTF8_To_GBK(const std::string& source)
{
	enum { GB2312 = 936 };

	unsigned long len = ::MultiByteToWideChar(CP_UTF8, NULL, source.c_str(), -1, NULL, NULL);
	if (len == 0)
		return std::string();
	wchar_t* wide_char_buffer = new wchar_t[len];
	::MultiByteToWideChar(CP_UTF8, NULL, source.c_str(), -1, wide_char_buffer, len);

	len = ::WideCharToMultiByte(GB2312, NULL, wide_char_buffer, -1, NULL, NULL, NULL, NULL);
	if (len == 0)
	{
		delete[] wide_char_buffer;
		return std::string();
	}
	char* multi_byte_buffer = new char[len];
	::WideCharToMultiByte(GB2312, NULL, wide_char_buffer, -1, multi_byte_buffer, len, NULL, NULL);

	std::string dest(multi_byte_buffer);
	delete[] wide_char_buffer;
	delete[] multi_byte_buffer;
	return dest;
}

bool IsSpam(string message)
{
	for (auto& c : message) {
		c = tolower(c);
	}

	for (int i = 0; i < words.size(); i++)
	{
		if (strstr(message.c_str(), words[i].c_str()) != NULL)
			return true;
	}
	return false;
}

class CEventNetWorkTextMessageReceived
{
public:
	char pad_0000[24]; //0x0000
	char m_info[8]; //0x0018
	char pad_0020[36]; //0x0020
}; //Size: 0x0044

using event_network_text_message_received_t = char __fastcall (CEventNetWorkTextMessageReceived* a1, DWORD64* a2, int a3);
typedef __int64(__cdecl* get_chat_data_t)(__int64 a1, __int64 a2, __int64 a3, const char* receivetext, BOOL a5);
event_network_text_message_received_t* m_event_network_text_message_received{};
get_chat_data_t m_get_chat_data{};

get_chat_data_t og_get_chat_data = nullptr;
__int64 __cdecl hk_get_chat_data(__int64 a1, __int64 a2, __int64 a3, const char* receivetext, BOOL a5)
{
	bool isspam = IsSpam(UTF8_To_GBK(receivetext));
	if (isspam)
		return 0;

	return og_get_chat_data(a1, a2, a3, receivetext, a5);
}

event_network_text_message_received_t* og_event_network_text_message_received = nullptr;
bool hk_event_network_text_message_received(CEventNetWorkTextMessageReceived* a1, DWORD64* a2, int a3)
{
	bool isspam = IsSpam(a1->m_info);
	if (isspam)
		return false;
	return og_event_network_text_message_received(a1, a2, a3);
}

DWORD Mainthread(HMODULE hModule)
{
	ifstream infile("C:\\ProgramData\\GTA5OnlineTools\\Config\\BlockWords.txt");
	string line;
	if (infile)
	{
		while (getline(infile, line))
		{
			for (auto& c : line) {
				c = tolower(c);
			}
			words.push_back(UTF8_To_GBK(line));
		}
	}
	infile.close();
	line.clear();

	MH_Initialize();

	pattern_batch main_batch;
	main_batch.add("EventNetWorkTextMessageReceived", "48 83 EC 28 4C 8B CA 48 85 D2 0F 84 ? ? ? ? 41 BA ? ? ? ? 45 3B C2 0F 85 ? ? ? ? 48 8D 51 18 48 8B C2 49 0B C1 83 E0 0F 0F 85 ? ? ? ? B8 ? ? ? ? 8D 48 7F 0F 28 02 41 0F 29 01 0F 28 4A 10 41 0F 29 49 ? 0F 28 42 20 41 0F 29 41 ? 0F 28 4A 30 41 0F 29 49 ? 0F 28 42 40 41 0F 29 41 ? 0F 28 4A 50 41 0F 29 49 ? 0F 28 42 60 41 0F 29 41 ? 0F 28 4A 70 4C 03 C9 48 03 D1 41 0F 29 49 ? 48 FF C8 75 AF 0F 28 02 41 0F 29 01 0F 28 4A 10 41 0F 29 49 ? 0F 28 42 20 41 0F 29 41 ? 0F 28 4A 30 41 0F 29 49 ? 0F 28 42 40 41 0F 29 41 ? 0F 28 4A 50 41 0F 29 49 ? 48 8B 42 60", [=](ptr_manage ptr)
		{
			m_event_network_text_message_received = ptr.as<event_network_text_message_received_t*>();
		});
	main_batch.add("get_chat_data", "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC 30 49 8B F8 44 8B 81 ? ? ? ?", [=](ptr_manage ptr)
		{
			m_get_chat_data = ptr.as<get_chat_data_t>();
		});
	main_batch.run();

	MH_CreateHook(m_get_chat_data, hk_get_chat_data, (LPVOID*)&og_get_chat_data);
	MH_CreateHook(m_event_network_text_message_received, hk_event_network_text_message_received, (LPVOID*)&og_event_network_text_message_received);
	MH_EnableHook(MH_ALL_HOOKS);

	Beep(600, 75);

	while (g_running)
	{
		if (GetAsyncKeyState(VK_END) & 0x8000)
		{
			Beep(500, 75);
			MH_Uninitialize();
			FreeLibraryAndExitThread(hModule, 0);
			return 0;
		}
	}

	return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		DisableThreadLibraryCalls(hModule);
		CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)Mainthread, hModule, NULL, NULL);
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
