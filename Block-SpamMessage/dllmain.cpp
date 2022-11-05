#include "pch.h"
#include "minhook/minhook.h"
#include "sigscan.h"

#include <iostream>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <codecvt>

#include <Windows.h>

#include <spdlog/spdlog.h>

using namespace std;

HMODULE hm;

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

PVOID m_receive_net_message{};

class datBitBuffer;
class InFrame;

typedef bool (*ReceiveNetMessage)(void* netConnectionManager, void* a2, InFrame* frame);
ReceiveNetMessage og_receive_net_message{};
using read_bitbuf_dword = bool(*)(datBitBuffer* buffer, PVOID read, int bits);
using read_bitbuf_string = bool(*)(datBitBuffer* buffer, char* read, int bits);
read_bitbuf_dword m_read_bitbuf_dword{};
read_bitbuf_string m_read_bitbuf_string{};

enum class eNetMessage : uint32_t {
	CMsgInvalid = 0xFFFFF,
	CMsgTextMessage = 0x24, // this one is for chat
	CMsgTextMessage2 = 0x0A // this one is for phone message
};

class datBitBuffer
{
public:
	datBitBuffer(uint8_t* data, uint32_t size) {
		m_data = data;
		m_bitOffset = 0;
		m_maxBit = size * 8;
		m_bitsRead = 0;
		m_curBit = 0;
		m_highestBitsRead = 0;
		m_flagBits = 0;
	}
	bool ReadDword(uint32_t* integer, int bits) {
		return m_read_bitbuf_dword(this, integer, bits);
	}
	bool ReadString(char* string, int bits) {
		return m_read_bitbuf_string(this, string, bits);
	}
public:
	uint8_t* m_data; //0x0000
	uint32_t m_bitOffset; //0x0008
	uint32_t m_maxBit; //0x000C
	uint32_t m_bitsRead; //0x0010
	uint32_t m_curBit; //0x0014
	uint32_t m_highestBitsRead; //0x0018
	uint8_t m_flagBits; //0x001C
};

class InFrame
{
public:
	enum class EventType
	{
		ConnectionClosed = 3,
		FrameReceived = 4,
		BandwidthExceeded = 6,
		OutOfMemory = 7
	};

	virtual ~InFrame() = default;

	virtual void destroy() = 0;
	virtual EventType get_event_type() = 0;
	virtual uint32_t _0x18() = 0;

	char pad_0008[56]; //0x0008
	uint32_t m_msg_id; //0x0040
	uint32_t m_connection_identifier; //0x0044
	InFrame* m_this; //0x0048
	uint32_t m_peer_id; //0x0050
	char pad_0050[36]; //0x0058
	uint32_t m_length; //0x0078
	char pad_007C[4]; //0x007C
	void* m_data; //0x0080
};
static_assert(sizeof(InFrame) == 0x88);

bool get_msg_type(eNetMessage& msgType, datBitBuffer& buffer)
{
	uint32_t pos;
	uint32_t magic;
	uint32_t length;
	uint32_t extended{};
	if ((buffer.m_flagBits & 2) != 0 || (buffer.m_flagBits & 1) == 0 ? (pos = buffer.m_curBit) : (pos = buffer.m_maxBit),
		buffer.m_bitsRead + 15 > pos || !buffer.ReadDword(&magic, 14) || magic != 0x3246 || !buffer.ReadDword(&extended, 1)) {
		msgType = eNetMessage::CMsgInvalid;
		return false;
	}
	length = extended ? 16 : 8;
	if ((buffer.m_flagBits & 1) == 0 ? (pos = buffer.m_curBit) : (pos = buffer.m_maxBit), length + buffer.m_bitsRead <= pos && buffer.ReadDword((uint32_t*)&msgType, length))
		return true;
	else
		return false;
}

bool receive_net_message(void* netConnectionManager, void* a2, InFrame* frame)
{
	if (frame->get_event_type() == InFrame::EventType::FrameReceived)
	{
		datBitBuffer buffer((uint8_t*)frame->m_data, frame->m_length);
		buffer.m_flagBits = 1;
		eNetMessage msgType;
		if (get_msg_type(msgType, buffer))
		{
			switch (msgType)
			{
			case eNetMessage::CMsgTextMessage:
			case eNetMessage::CMsgTextMessage2:
			{
				char buf[0x100]{};
				if (buffer.ReadString(buf, 0x100))
				{
					if (IsSpam(UTF8_To_GBK(buf)))
						return true;
				}
			}
			default:
				break;
			}
		}
	}

	return og_receive_net_message(netConnectionManager, a2, frame);
}

void freeandexit()
{
#ifdef _DEBUG
	FreeConsole();
#endif // _DEBUG
	MH_DisableHook(MH_ALL_HOOKS);
	MH_Uninitialize();
}

void loadHook() {
	if (MH_Initialize() != MH_OK)
		spdlog::error("Failed to init minhook");

	pattern_batch main_batch;
	main_batch.add("NMR", "48 83 EC 20 4C 8B 71 50 33 ED", [=](ptr_manage ptr)
		{
			spdlog::debug("NMR found.");
			m_receive_net_message = ptr.sub(0x19).as<PVOID>();
		});

	main_batch.add("RBWD", "48 89 74 24 ? 57 48 83 EC 20 48 8B D9 33 C9 41 8B F0 8A", [=](ptr_manage ptr)
		{
			spdlog::debug("RBWD found.");
			m_read_bitbuf_dword = ptr.sub(5).as<decltype(m_read_bitbuf_dword)>();
		});

	main_batch.add("RBS", "E8 ? ? ? ? 48 8D 4F 3C", [=](ptr_manage ptr)
		{
			spdlog::debug("RBS found.");
			m_read_bitbuf_string = ptr.add(1).rip().as<decltype(m_read_bitbuf_string)>();
		});
	main_batch.run();

	if (MH_CreateHook(m_receive_net_message, receive_net_message, (LPVOID*)&og_receive_net_message) != MH_OK)
		spdlog::error("Failed to hook message receie event");

	if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK)
		spdlog::error("Failed to hook message receie event");
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	hm = hModule;

	if (ul_reason_for_call == DLL_PROCESS_ATTACH)
	{
#ifdef _DEBUG
		AllocConsole();
		freopen("CONOUT$", "w", stdout);
		std::wcout.imbue(std::locale("chs"));
#endif // _DEBUG

		ifstream infile("C:\\ProgramData\\GTA5OnlineTools\\Config\\BlockWords.txt");
		if (infile.is_open())
		{
			std::string line;
			while (getline(infile, line))
			{
				for (auto& c : line) {
					c = tolower(c);
				}
				words.push_back(line);
			}
			infile.close();
			spdlog::info(UTF8_To_GBK(std::format("成功加载{}条违禁词", words.size())));
		}
		else
			spdlog::info(UTF8_To_GBK("加载违禁词失败"));

		spdlog::info("DLL loaded!");
	}
	else if (ul_reason_for_call == DLL_PROCESS_DETACH)
		freeandexit();

	return true;
}
