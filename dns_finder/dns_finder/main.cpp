#include <stdio.h>
#include "xdns.h"
#include <atomic>
#include <thread>
#include <string>
#include <vector>
#include <mutex>
#include <iostream>
#include <fstream>
#include <iomanip>
#if defined(_MSC_VER)
#include <WinSock2.h>
#pragma comment(lib,"ws2_32")
#endif

std::string g_domain_name;
std::atomic<std::uint32_t> g_count;
std::uint32_t g_start_ip = 0x00000001;
std::uint32_t g_end_ip = 0xE0000000;
#define LAST_WAIT_SECONDS 5
std::mutex g_cs;
std::vector<std::string> g_ip_vec;
std::vector<std::string> g_dns_vec;

void WorkThread(std::uint32_t start_ip, std::uint32_t end_ip)
{
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	sockaddr_in addr = { 0 };
	addr.sin_family = AF_INET;
	addr.sin_port = htons(53);
	char buf[1024];
	sendto(s, buf, 1, 0, (sockaddr*)&addr, sizeof(addr));
	std::thread t([s](std::uint32_t start_ip, std::uint32_t end_ip){
		xdns::DnsQuery query;
		sockaddr_in addr;
		addr.sin_family = AF_INET;
		addr.sin_port = htons(53);
		query.set(0x1234, g_domain_name.c_str(), 1);
		while (start_ip <= end_ip)
		{
			addr.sin_addr.S_un.S_addr = htonl(start_ip);
			if (sendto(s, query.get_dns_package_buffer(), query.get_dns_package_size(), 0, (sockaddr*)&addr, sizeof(addr)) < 0)
			{
				std::cout << "sendto error.\n";
				std::exit(-1);
			}
			++g_count;
			++start_ip;
		}
		std::this_thread::sleep_for(std::chrono::seconds(LAST_WAIT_SECONDS));
		closesocket(s);
	}, start_ip, end_ip);
	int len = 0;
	int fromlen = 0;
	for (;;)
	{
		fromlen = sizeof(addr);
		len = recvfrom(s, buf, 1024, 0, (sockaddr*)&addr, &fromlen);
		if (len <= 0)
			break;

		std::lock_guard<std::mutex> guard(g_cs);
		xdns::DnsRecordParser parser;
		parser.set_package_buffer(buf, len);
		parser.begin();
		int type = parser.get_current_section_type();
		bool has_ip = false;
		for (; parser.valid_section_type(); type = parser.next())
		{
			if (type == xdns::section_type_answer && parser.get_type() == xdns::type_A)
			{
				g_ip_vec.push_back(parser.rdata_as_ip());
				has_ip = true;
			}
		}
		if(has_ip)
			g_dns_vec.push_back(xdns::ip_to_string(&addr.sin_addr.S_un.S_addr, 4));
	}
	t.join();
}
int main(int argc, char** argv)
{
	WSADATA wd = { 0 };
	WSAStartup(MAKEWORD(2, 2), &wd);
	if (argc != 3)
	{
		printf(
			"usage: dns_finder.exe www.google.com 17\n"
			"you can substitute www.google.com to any domain name.\n"
			"17 means thread count to send dns querys.\n");
		return -1;
	}
	g_domain_name = argv[1];
	int thread_count = 20;
	try
	{
		thread_count = std::stoi(argv[2]);
		if (thread_count <= 0 || thread_count >= 2000)
			thread_count = 100;
	}
	catch (...)
	{
		printf("can not covert arg %s to number.\n", argv[2]);
		return -1;
	}
	printf("query thread count is %d\n", thread_count);
	std::vector<std::thread> thread_vec;
	std::uint32_t interval = (g_end_ip - g_start_ip + 1) / thread_count;
	for (int i = 0; i < thread_count; ++i)
	{
		std::uint32_t start = g_start_ip + i * interval;
		std::uint32_t end = g_start_ip + (i + 1)*interval - 1;
		if (i == thread_count - 1)
			end = g_end_ip;
		thread_vec.push_back(std::thread(WorkThread, start, end));
	}
	std::uint32_t work_count = g_end_ip - g_start_ip + 1;
	int begin_exit = 0;
	std::ofstream fdns("dns.txt");
	std::ofstream fip("ip.txt");
	for (;;)
	{
		if (work_count == g_count)
			++begin_exit;
		if (begin_exit > 3)
			break;
		std::this_thread::sleep_for(std::chrono::seconds(2));
		printf("processed:%.2f%%\n", 100 * 1.0*g_count / work_count);
		std::lock_guard<std::mutex> guard(g_cs);
		if (g_ip_vec.size())
		{
			for (auto& ip : g_ip_vec)
			{
				fip << ip << std::endl;
				std::cout << "find ip:" << ip << std::endl;
			}
			g_ip_vec.clear();
		}
		if (g_dns_vec.size())
		{
			for (auto& v : g_dns_vec)
			{
				fdns << v << std::endl;
				std::cout << "find avaliable dns:" << v << std::endl;
			}
			g_dns_vec.clear();
		}
	}
	for (auto& v : thread_vec)
		v.join();
	printf("work done.\n");
}