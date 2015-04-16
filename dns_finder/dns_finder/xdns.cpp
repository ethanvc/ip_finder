#include "xdns.h"
#include <Winsock2.h>
namespace xdns
{
	DnsQuery::DnsQuery()
	{
		id_ = 0;
		qtype_ = 0;
		data_ = 0;
		buffer_size_ = 0;
		content_size_ = 0;
	}

	void DnsQuery::set(uint16_t id, const string& qname, uint16_t qtype)
	{
		id_ = id;
		qname_ = qname;
		qtype_ = qtype;
		construct_dns_package();
	}

	void DnsQuery::set_new_id(uint16_t id)
	{
		id_ = id;
		construct_dns_package();
	}

	const char* DnsQuery::get_dns_package_buffer()
	{
		return data_;
	}

	int DnsQuery::get_dns_package_size()
	{
		return content_size_;
	}

	void DnsQuery::construct_dns_package()
	{
		int new_size = 2 + 2 + 8 + (static_cast<int>(qname_.size() + 2)) + 2 + 2;
		if (!data_ || buffer_size_ < new_size)
		{
			if (data_)
				delete[] data_;
			data_ = new char[new_size];
			if (!data_)
			{
				buffer_size_ = 0;
				content_size_ = 0;
				return;
			}
			buffer_size_ = new_size;
		}
		content_size_ = new_size;
		memset(data_, 0, content_size_);
		*(uint16_t*)data_ = htons(id_);
		*(uint16_t*)(data_ + 2) = htons(0x100);
		*(uint16_t*)(data_ + 4) = htons(1);
		char* qname = data_ + 12;
		char* p = qname + 1;
		for (auto& v : qname_)
		{
			if (v == '.')
			{
				*(unsigned char*)qname = static_cast<unsigned char>(p - qname - 1);
				qname = p;
			}
			else
			{
				*p = v;
			}
			++p;
		}
		*(unsigned char*)qname = static_cast<unsigned char>(p - qname - 1);
		*p = 0;
		++p;
		*(uint16_t*)p = htons(qtype_);
		*(uint16_t*)(p + 2) = htons(1);
	}

	int DnsRecordParser::set_package_buffer(const char* buffer, int length)
	{
		clearall();
		if (!buffer || length < 12)
			return -1;
		do 
		{
			packet_ = buffer;
			length_ = length;
			return 0;
		} while (false);
		clearall();
		return -1;
	}

	int DnsRecordParser::begin()
	{
		if (!length_)
			return -1;
		pos_ = packet_ + 12;
		current_section_type_ = 0;
		next_index_ = 0;
		return next();
	}

	int DnsRecordParser::next()
	{
		int len = 0;
		for (;;)
		{
			if (current_section_type_ < 0 || current_section_type_ >= 4)
				return get_current_section_type();
			if (next_index_ >= get_section_count(current_section_type_))
			{
				next_index_ = 0;
				++current_section_type_;
				continue;
			}
			if (current_section_type_ == 0)
			{//question section
				len = read_name(pos_, &name_);
				if (len < 0)
				{
					current_section_type_ = -1;
					break;
				}
				pos_ += len;
				if (pos_ + 4 > packet_ + length_)
				{
					current_section_type_ = -1;
					break;
				}
				type_ = ntohs(*(uint16_t*)pos_);
				class_ = ntohs(*(uint16_t*)(pos_ + 2));
				pos_ += 4;
				break;
			}
			else
			{
				len = read_name(pos_, &name_);
				if (len < 0)
				{
					current_section_type_ = -1;
					break;
				}
				pos_ += len;
				if (pos_ + 10 > packet_ + length_)
				{
					current_section_type_ = -1;
					break;
				}
				type_ = htons(*(uint16_t*)pos_);
				class_ = htons(*(uint16_t*)(pos_ + 2));
				ttl_ = htonl(*(uint32_t*)(pos_ + 4));
				rdata_size_ = htons(*(uint16_t*)(pos_ + 8));
				pos_ += 10;
				rdata_ = pos_;
				if (pos_ + rdata_size_ > packet_ + length_)
				{
					current_section_type_ = -1;
					break;
				}
				pos_ += rdata_size_;
				break;
			}
		}
		++next_index_;
		return get_current_section_type();
	}

	int DnsRecordParser::get_current_section_type()
	{
		return current_section_type_;
	}

	uint16_t DnsRecordParser::get_id()
	{
		if (packet_)
		{
			return ntohs(*(uint16_t*)(packet_ + 0));
		}
		else
			return 0;
	}

	uint16_t DnsRecordParser::get_flags()
	{
		if (!packet_)
			return 0;
		return ntohs(*(uint16_t*)(packet_ + 2));
	}

	uint16_t DnsRecordParser::get_section_count(int section_type)
	{
		if (!packet_ || section_type < 0 || section_type > 3)
			return 0;
		return ntohs(*(uint16_t*)(packet_ + 4 + section_type * 2));
	}

	const char* DnsRecordParser::get_name()
	{
		return name_.c_str();
	}

	uint16_t DnsRecordParser::get_type()
	{
		return type_;
	}

	uint16_t DnsRecordParser::get_class()
	{
		return class_;
	}

	uint32_t DnsRecordParser::get_ttl()
	{
		return ttl_;
	}

	const char* DnsRecordParser::get_rdata()
	{
		return rdata_;
	}

	uint16_t DnsRecordParser::get_rdata_size()
	{
		return rdata_size_;
	}

	const char* DnsRecordParser::rdata_as_cname()
	{
		if (current_section_type_ >= 0 && current_section_type_ <= 3 && type_ == 0x0005)
		{
			if (read_name(rdata_, &sbuf_) >= 0)
				return sbuf_.c_str();
		}
		return "";
	}

	const char* DnsRecordParser::rdata_as_ip()
	{
		if (valid_section_type() && type_ == type_A)
			sbuf_ = ip_to_string(rdata_, rdata_size_);
		else
			sbuf_.clear();
		return sbuf_.c_str();
	}

	bool DnsRecordParser::valid_section_type()
	{
		if (current_section_type_ >= 0 && current_section_type_ <= 3)
			return true;
		else
			return false;
	}

	void DnsRecordParser::clearall()
	{
		packet_ = 0;
		length_ = 0;
		current_section_type_ = 0;
		next_index_ = 0;
		type_ = 0;
		class_ = 0;
		ttl_ = 0;
		rdata_ = 0;
		rdata_size_ = 0;
	}

	int DnsRecordParser::read_name(const char* pos, std::string* out)
	{
		const char* p = pos;
		const char* end = packet_ + length_;
		// Count number of seen bytes to detect loops.
		int seen = 0;
		// Remember how many bytes were consumed before first jump.
		unsigned consumed = 0;

		if (pos >= end)
			return -1;

		if (out) {
			out->clear();
			out->reserve(255);//max size of name
		}

		for (;;) {
			// The first two bits of the length give the type of the length. It's
			// either a direct length or a pointer to the remainder of the name.
			switch (*p & 0xc0) {
			case 0xc0: {
				if (p + sizeof(uint16_t) > end)
					return 0;
				if (consumed == 0) {
					consumed = static_cast<unsigned>(p - pos + sizeof(uint16_t));
					if (!out)
						return consumed;  // If name is not stored, that's all we need.
				}
				seen += sizeof(uint16_t);
				// If seen the whole packet, then we must be in a loop.
				if (seen > length_)
					return 0;
				uint16_t offset = ntohs(*(uint16_t*)p);
				offset &= 0x3fff;
				p = packet_ + offset;
				if (p >= end)
					return 0;
				break;
			}
			case 0x0: {
				uint8_t label_len = *p;
				++p;
				// Note: root domain (".") is NOT included.
				if (label_len == 0) {
					if (consumed == 0) {
						consumed = static_cast<unsigned>(p - pos);
					}  // else we set |consumed| before first jump
					return consumed;
				}
				if (p + label_len >= end)
					return -1;  // Truncated or missing label.
				if (out) {
					if (!out->empty())
						out->append(".");
					out->append(p, label_len);
				}
				p += label_len;
				seen += 1 + label_len;
				break;
			}
			default:
				// unhandled label type
				return -1;
			}
		}
	}
}