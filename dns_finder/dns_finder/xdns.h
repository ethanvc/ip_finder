#pragma once
#include <cstdint>
#include <string>
namespace xdns
{
	const int section_type_question = 0;
	const int section_type_answer = 1;
	const int section_type_authority = 2;
	const int section_type_additional = 3;

	const std::uint16_t type_A = 1; // a host address
	using namespace std;
	class DnsQuery
	{
	public:
		DnsQuery();
		void set(uint16_t id, const string& qname, uint16_t qtype);
		void set_new_id(uint16_t id);
		const char* get_dns_package_buffer();
		int get_dns_package_size();
	private:
		string qname_;
		uint16_t id_;
		uint16_t qtype_;
		char* data_;
		int buffer_size_;
		int content_size_;

		void construct_dns_package();
	};

	class DnsRecordParser
	{
	public:
		DnsRecordParser(){ clearall(); }
		int set_package_buffer(const char* buffer, int size);
		int begin();
		int next();
		int get_current_section_type();//0 1 2 3 4 
		uint16_t get_id();
		uint16_t get_flags();
		uint16_t get_section_count(int section_type);
		const char* get_name();
		uint16_t get_type();
		uint16_t get_class();
		uint32_t get_ttl();
		const char* get_rdata();
		uint16_t get_rdata_size();
		const char* rdata_as_cname();
		const char* rdata_as_ip();
		bool valid_section_type();
	private:
		const char* packet_;
		int length_;
		const char* pos_;
		int current_section_type_;
		int next_index_;
		std::string name_;
		uint16_t type_;
		uint16_t class_;
		uint32_t ttl_;
		const char* rdata_;
		uint16_t rdata_size_;
		std::string sbuf_;

		void clearall();
		bool skip_question_section();
		int read_name(const char* pos, std::string* out);
	};

	inline std::string ip_to_string(const void* p, size_t size)
	{
		std::string s;
		if (size == 4)
		{
			for (size_t i = 0; i < size; ++i)
			{
				unsigned char ch = *((const unsigned char*)p + i);
				if (s.size())
					s += '.';
				s += std::to_string(ch);
			}
		}
		return s;
	}
}