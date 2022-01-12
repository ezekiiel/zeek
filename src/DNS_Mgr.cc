// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/DNS_Mgr.h"

#include "zeek/zeek-config.h"

#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <algorithm>

#ifdef TIME_WITH_SYS_TIME
#include <sys/time.h>
#include <time.h>
#elif defined(HAVE_SYS_TIME_H)
#include <sys/time.h>
#else
#include <time.h>
#endif

#include <ares.h>
#include <ares_dns.h>
#include <ares_nameser.h>

#include "zeek/3rdparty/doctest.h"
#include "zeek/DNS_Mapping.h"
#include "zeek/Event.h"
#include "zeek/Expr.h"
#include "zeek/Hash.h"
#include "zeek/ID.h"
#include "zeek/IntrusivePtr.h"
#include "zeek/NetVar.h"
#include "zeek/Reporter.h"
#include "zeek/RunState.h"
#include "zeek/Val.h"
#include "zeek/ZeekString.h"
#include "zeek/iosource/Manager.h"

// Number of seconds we'll wait for a reply.
constexpr int DNS_TIMEOUT = 5;

// The maximum allowed number of pending asynchronous requests.
constexpr int MAX_PENDING_REQUESTS = 20;

namespace zeek::detail
	{

static void hostbyaddr_cb(void* arg, int status, int timeouts, struct hostent* hostent);
static void addrinfo_cb(void* arg, int status, int timeouts, struct ares_addrinfo* result);
static void query_cb(void* arg, int status, int timeouts, unsigned char* buf, int len);
static void sock_cb(void* data, int s, int read, int write);

class DNS_Request
	{
public:
	DNS_Request(const char* host, int af, int request_type);
	DNS_Request(const IPAddr& addr);
	~DNS_Request();

	const char* Host() const { return host; }
	const IPAddr& Addr() const { return addr; }
	int Family() const { return family; }
	int RequestType() const { return request_type; }
	bool IsTxt() const { return request_type == 16; }

	void MakeRequest(ares_channel channel);

	bool RequestPending() const { return request_pending; }
	void RequestDone() { request_pending = false; }

private:
	char* host = nullptr;
	IPAddr addr;
	int family = 0; // address family query type for host requests
	int request_type = 0; // Query type
	bool request_pending = false;
	unsigned char* query = nullptr;
	static uint16_t request_id;
	};

uint16_t DNS_Request::request_id = 0;

DNS_Request::DNS_Request(const char* host, int af, int request_type)
	: host(util::copy_string(host)), family(af), request_type(request_type)
	{
	}

DNS_Request::DNS_Request(const IPAddr& addr) : addr(addr)
	{
	family = addr.GetFamily() == IPv4 ? AF_INET : AF_INET6;
	request_type = T_PTR;
	}

DNS_Request::~DNS_Request()
	{
	delete[] host;
	if ( query )
		ares_free_string(query);
	}

void DNS_Request::MakeRequest(ares_channel channel)
	{
	request_pending = true;

	// It's completely fine if this rolls over. It's just to keep the query ID different
	// from one query to the next, and it's unlikely we'd do 2^16 queries so fast that
	// all of them would be in flight at the same time.
	DNS_Request::request_id++;

	// We do normal host and address lookups via the specialized methods for them
	// because those will attempt to do file lookups as well internally before
	// reaching out to the DNS server. The remaining lookup types all use
	// ares_create_query() and ares_send() for more genericness.
	if ( request_type == T_A || request_type == T_AAAA )
		{
		// Use getaddrinfo here because it gives us the ttl information. If we don't
		// care about TTL, we could use gethostbyname instead.
		ares_addrinfo_hints hints = {ARES_AI_CANONNAME, family, 0, 0};
		ares_getaddrinfo(channel, host, NULL, &hints, addrinfo_cb, this);
		}
	else if ( request_type == T_PTR )
		{
		const uint32_t* bytes;
		int len = addr.GetBytes(&bytes);
		ares_gethostbyaddr(channel, bytes, len, family, hostbyaddr_cb, this);
		}
	else
		{
		unsigned char* query = NULL;
		int len = 0;
		int status = ares_create_query(host, C_IN, request_type, DNS_Request::request_id, 0, &query,
		                               &len, 0);
		if ( status != ARES_SUCCESS )
			{
			printf("ares_create_query failed: %s\n", ares_strerror(status));
			return;
			}

		// Store this so it can be destroyed when the request is destroyed.
		this->query = query;
		ares_send(channel, query, len, query_cb, this);
		}
	}

/**
 * Called in response to ares_gethostbyaddr requests. Sends the hostent data to the
 * DNS manager via AddResult().
 */
static void hostbyaddr_cb(void* arg, int status, int timeouts, struct hostent* host)
	{
	if ( ! host || status != ARES_SUCCESS )
		{
		// TODO: reporter warning or something here, or just give up on it?
		printf("Failed hostbyaddr request: %s\n", ares_strerror(status));
		return;
		}

	auto req = reinterpret_cast<DNS_Request*>(arg);
	// TOOD: the old code could get TTL data from hostbyaddr reqeusts, but c-ares doesn't
	// provide that information. does it matter?
	dns_mgr->AddResult(req, host, 0);
	}

/**
 * Called in response to ares_getaddrinfo requests. Builds a hostent structure from
 * the result data and sends it to the DNS manager via Addresult().
 */
static void addrinfo_cb(void* arg, int status, int timeouts, struct ares_addrinfo* result)
	{
	if ( status != ARES_SUCCESS )
		{
		// TODO: reporter warning or something here, or just give up on it?
		printf("Failed addrinfo request: %s\n", ares_strerror(status));
		ares_freeaddrinfo(result);
		return;
		}

	// TODO: the existing code doesn't handle hostname aliases at all. Should we?
	// TODO: handle IPv6 mode

	std::vector<in_addr*> addrs;
	for ( ares_addrinfo_node* entry = result->nodes; entry != NULL; entry = entry->ai_next )
		addrs.push_back(&reinterpret_cast<sockaddr_in*>(entry->ai_addr)->sin_addr);

	// Push a null on the end so the addr list has a final point during later parsing.
	addrs.push_back(NULL);

	struct hostent he;
	he.h_name = util::copy_string(result->name);
	he.h_aliases = NULL;
	he.h_addrtype = AF_INET;
	he.h_length = sizeof(in_addr);
	he.h_addr_list = reinterpret_cast<char**>(addrs.data());

	auto req = reinterpret_cast<DNS_Request*>(arg);
	dns_mgr->AddResult(req, &he, result->nodes[0].ai_ttl);

	delete[] he.h_name;

	ares_freeaddrinfo(result);
	}

/**
 * Called in response to all other query types.
 */
static void query_cb(void* arg, int status, int timeouts, unsigned char* buf, int len)
	{
	if ( status != ARES_SUCCESS )
		{
		// TODO: reporter warning or something here, or just give up on it?
		return;
		}

	// TODO: implement this
	auto req = reinterpret_cast<DNS_Request*>(arg);
	switch ( req->RequestType() )
		{
		case T_TXT:
			{
			struct ares_txt_reply* reply;
			int r = ares_parse_txt_reply(buf, len, &reply);
			if ( r != ARES_SUCCESS )
				{
				// TODO: reporter warning or something here, or just give up on it?
				return;
				}

			// Use a hostent to send the data into AddResult(). We only care about
			// setting the host field, but everything else should be zero just for
			// safety.
			// TODO: this is kinda gross, but I guess it works. Maybe a good impetus
			// to redo DNS_Mapping?
			// TODO: should we handle multi-part TXT responses here?
			struct hostent he;
			memset(&he, 0, sizeof(struct hostent));
			he.h_name = util::copy_string(reinterpret_cast<const char*>(reply->txt));
			dns_mgr->AddResult(req, &he, 0);

			ares_free_data(reply);
			break;
			}
		default:
			reporter->Error("Requests of type %d are unsupported\n", req->RequestType());
			break;
		}
	}

/**
 * Called when the c-ares socket changes state, whcih indicates that it's connected to
 * some source of data (either a host file or a DNS server). This indicates that we're
 * able to do lookups against c-ares now and should activate the IOSource.
 */
static void sock_cb(void* data, int s, int read, int write)
	{
	if ( read == 1 )
		iosource_mgr->RegisterFd(s, reinterpret_cast<DNS_Mgr*>(data));
	else
		iosource_mgr->UnregisterFd(s, reinterpret_cast<DNS_Mgr*>(data));
	}

DNS_Mgr::DNS_Mgr(DNS_MgrMode arg_mode) : mode(arg_mode)
	{
	ares_library_init(ARES_LIB_INIT_ALL);
	}

DNS_Mgr::~DNS_Mgr()
	{
	ares_cancel(channel);
	ares_destroy(channel);
	ares_library_cleanup();
	}

void DNS_Mgr::InitSource()
	{
	if ( did_init )
		return;

	ares_init(&channel);

	ares_options options;
	int optmask = 0;

	options.flags = ARES_FLAG_STAYOPEN;
	optmask |= ARES_OPT_FLAGS;

	options.timeout = DNS_TIMEOUT;
	optmask |= ARES_OPT_TIMEOUT;

	options.sock_state_cb = sock_cb;
	options.sock_state_cb_data = this;
	optmask |= ARES_OPT_SOCK_STATE_CB;

	int status = ares_init_options(&channel, &options, optmask);
	if ( status != ARES_SUCCESS )
		reporter->FatalError("Failed to initialize c-ares for DNS resolution: %s\n",
		                     ares_strerror(status));

	// Note that Init() may be called by way of LookupHost() during the act of
	// parsing a hostname literal (e.g. google.com), so we can't use a
	// script-layer option to configure the DNS resolver as it may not be
	// configured to the user's desired address at the time when we need to to
	// the lookup.
	auto dns_resolver = getenv("ZEEK_DNS_RESOLVER");
	if ( dns_resolver )
		{
		ares_addr_node servers;
		servers.next = nullptr;

		auto dns_resolver_addr = IPAddr(dns_resolver);
		struct sockaddr_storage ss = {0};

		if ( dns_resolver_addr.GetFamily() == IPv4 )
			{
			struct sockaddr_in* sa = (struct sockaddr_in*)&ss;
			sa->sin_family = AF_INET;
			dns_resolver_addr.CopyIPv4(&sa->sin_addr);

			servers.family = AF_INET;
			memcpy(&(servers.addr.addr4), &sa->sin_addr, sizeof(struct in_addr));
			}
		else
			{
			struct sockaddr_in6* sa = (struct sockaddr_in6*)&ss;
			sa->sin6_family = AF_INET6;
			dns_resolver_addr.CopyIPv6(&sa->sin6_addr);

			servers.family = AF_INET6;
			memcpy(&(servers.addr.addr6), &sa->sin6_addr, sizeof(ares_in6_addr));
			}

		ares_set_servers(channel, &servers);
		}

	did_init = true;
	}

void DNS_Mgr::InitPostScript()
	{
	dm_rec = id::find_type<RecordType>("dns_mapping");

	// Registering will call InitSource(), which sets up all of the DNS library stuff
	iosource_mgr->Register(this, true);

	// Load the DNS cache from disk, if it exists.
	std::string cache_dir = dir.empty() ? dir : ".";
	cache_name = util::fmt("%s/%s", cache_dir.c_str(), ".zeek-dns-cache");
	LoadCache(cache_name);
	}

static TableValPtr fake_name_lookup_result(const char* name)
	{
	hash128_t hash;
	KeyedHash::StaticHash128(name, strlen(name), &hash);
	auto hv = make_intrusive<ListVal>(TYPE_ADDR);
	hv->Append(make_intrusive<AddrVal>(reinterpret_cast<const uint32_t*>(&hash)));
	return hv->ToSetVal();
	}

static const char* fake_text_lookup_result(const char* name)
	{
	return util::fmt("fake_text_lookup_result_%s", name);
	}

static const char* fake_addr_lookup_result(const IPAddr& addr)
	{
	return util::fmt("fake_addr_lookup_result_%s", addr.AsString().c_str());
	}

static void resolve_lookup_cb(DNS_Mgr::LookupCallback* callback, TableValPtr result)
	{
	callback->Resolved(std::move(result));
	delete callback;
	}

static void resolve_lookup_cb(DNS_Mgr::LookupCallback* callback, const char* result)
	{
	callback->Resolved(result);
	delete callback;
	}

ValPtr DNS_Mgr::Lookup(const char* name, int request_type)
	{
	if ( mode == DNS_FAKE && request_type == T_TXT )
		return make_intrusive<StringVal>(fake_text_lookup_result(name));

	if ( mode != DNS_PRIME && request_type == T_TXT )
		{
		if ( auto val = LookupTextInCache(name, false) )
			return val;
		}

	switch ( mode )
		{
		case DNS_PRIME:
			{
			auto req = new DNS_Request(name, AF_UNSPEC, request_type);
			req->MakeRequest(channel);
			return empty_addr_set();
			}

		case DNS_FORCE:
			reporter->FatalError("can't find DNS entry for %s (req type %d) in cache", name,
			                     request_type);
			return nullptr;

		case DNS_DEFAULT:
			{
			auto req = new DNS_Request(name, AF_UNSPEC, request_type);
			req->MakeRequest(channel);
			Resolve();

			// Call LookupHost() a second time to get the newly stored value out of the cache.
			return Lookup(name, request_type);
			}

		default:
			reporter->InternalError("bad mode %d in DNS_Mgr::Lookup", mode);
			return nullptr;
		}

	return nullptr;
	}

TableValPtr DNS_Mgr::LookupHost(const char* name)
	{
	if ( mode == DNS_FAKE )
		return fake_name_lookup_result(name);

	// Check the cache before attempting to look up the name remotely.
	if ( mode != DNS_PRIME )
		{
		if ( auto val = LookupNameInCache(name, false, true) )
			return val;
		}

	// Not found, or priming.
	switch ( mode )
		{
		case DNS_PRIME:
			{
			// We pass T_A here and below, but because we're passing AF_UNSPEC
			// c-ares will attempt to look up both ipv4 and ipv6 at the same time.
			auto req = new DNS_Request(name, AF_UNSPEC, false);
			req->MakeRequest(channel);
			return empty_addr_set();
			}

		case DNS_FORCE:
			reporter->FatalError("can't find DNS entry for %s in cache", name);
			return nullptr;

		case DNS_DEFAULT:
			{
			// We pass T_A here and below, but because we're passing AF_UNSPEC
			// c-ares will attempt to look up both ipv4 and ipv6 at the same time.
			auto req = new DNS_Request(name, AF_UNSPEC, false);
			req->MakeRequest(channel);
			Resolve();

			// Call LookupHost() a second time to get the newly stored value out of the cache.
			return LookupHost(name);
			}

		default:
			reporter->InternalError("bad mode in DNS_Mgr::LookupHost");
			return nullptr;
		}
	}

ValPtr DNS_Mgr::LookupAddr(const IPAddr& addr)
	{
	// Check the cache before attempting to look up the name remotely.
	if ( mode != DNS_PRIME )
		{
		if ( auto val = LookupAddrInCache(addr, false, true) )
			return val;
		}

	// Not found, or priming.
	switch ( mode )
		{
		case DNS_PRIME:
			{
			auto req = new DNS_Request(addr);
			req->MakeRequest(channel);
			return make_intrusive<StringVal>("<none>");
			}

		case DNS_FORCE:
			reporter->FatalError("can't find DNS entry for %s in cache", addr.AsString().c_str());
			return nullptr;

		case DNS_DEFAULT:
			{
			auto req = new DNS_Request(addr);
			req->MakeRequest(channel);
			Resolve();

			// Call LookupAddr() a second time to get the newly stored value out of the cache.
			return LookupAddr(addr);
			}

		default:
			reporter->InternalError("bad mode in DNS_Mgr::LookupAddr");
			return nullptr;
		}
	}

void DNS_Mgr::LookupHost(const char* name, LookupCallback* callback)
	{
	if ( mode == DNS_FAKE )
		{
		resolve_lookup_cb(callback, fake_name_lookup_result(name));
		return;
		}

	// Do we already know the answer?
	if ( auto addrs = LookupNameInCache(name, true, false) )
		{
		resolve_lookup_cb(callback, std::move(addrs));
		return;
		}

	AsyncRequest* req = nullptr;

	// If we already have a request waiting for this host, we don't need to make
	// another one. We can just add the callback to it and it'll get handled
	// when the first request comes back.
	AsyncRequestNameMap::iterator i = asyncs_names.find(name);
	if ( i != asyncs_names.end() )
		req = i->second;
	else
		{
		// A new one.
		req = new AsyncRequest{};
		req->name = name;
		asyncs_queued.push_back(req);
		asyncs_names.emplace_hint(i, name, req);
		}

	req->callbacks.push_back(callback);

	// There may be requests in the queue that haven't been processed yet
	// so go ahead and reissue them, even if this method didn't change
	// anything.
	IssueAsyncRequests();
	}

void DNS_Mgr::LookupAddr(const IPAddr& host, LookupCallback* callback)
	{
	if ( mode == DNS_FAKE )
		{
		resolve_lookup_cb(callback, fake_addr_lookup_result(host));
		return;
		}

	// Do we already know the answer?
	if ( auto name = LookupAddrInCache(host, true, false) )
		{
		resolve_lookup_cb(callback, name->CheckString());
		return;
		}

	AsyncRequest* req = nullptr;

	// If we already have a request waiting for this host, we don't need to make
	// another one. We can just add the callback to it and it'll get handled
	// when the first request comes back.
	AsyncRequestAddrMap::iterator i = asyncs_addrs.find(host);
	if ( i != asyncs_addrs.end() )
		req = i->second;
	else
		{
		// A new one.
		req = new AsyncRequest{};
		req->host = host;
		asyncs_queued.push_back(req);
		asyncs_addrs.emplace_hint(i, host, req);
		}

	req->callbacks.push_back(callback);

	// There may be requests in the queue that haven't been processed yet
	// so go ahead and reissue them, even if this method didn't change
	// anything.
	IssueAsyncRequests();
	}

void DNS_Mgr::Lookup(const char* name, int request_type, LookupCallback* callback)
	{
	if ( mode == DNS_FAKE )
		{
		resolve_lookup_cb(callback, fake_text_lookup_result(name));
		return;
		}

	// Do we already know the answer?
	if ( auto txt = LookupTextInCache(name, true) )
		{
		resolve_lookup_cb(callback, txt->CheckString());
		return;
		}

	AsyncRequest* req = nullptr;

	// Have we already a request waiting for this host?
	AsyncRequestTextMap::iterator i = asyncs_texts.find(name);
	if ( i != asyncs_texts.end() )
		req = i->second;
	else
		{
		// A new one.
		req = new AsyncRequest{};
		req->name = name;
		req->is_txt = true;
		asyncs_queued.push_back(req);
		asyncs_texts.emplace_hint(i, name, req);
		}

	req->callbacks.push_back(callback);

	IssueAsyncRequests();
	}

void DNS_Mgr::Resolve()
	{
	int nfds = 0;
	struct timeval *tvp, tv;
	fd_set read_fds, write_fds;

	tv.tv_sec = DNS_TIMEOUT;
	tv.tv_usec = 0;

	for ( int i = 0; i < MAX_PENDING_REQUESTS; i++ )
		{
		FD_ZERO(&read_fds);
		FD_ZERO(&write_fds);
		nfds = ares_fds(channel, &read_fds, &write_fds);
		if ( nfds == 0 )
			break;

		tvp = ares_timeout(channel, &tv, &tv);
		select(nfds, &read_fds, &write_fds, NULL, tvp);
		ares_process(channel, &read_fds, &write_fds);
		}
	}

void DNS_Mgr::Event(EventHandlerPtr e, DNS_Mapping* dm)
	{
	if ( e )
		event_mgr.Enqueue(e, BuildMappingVal(dm));
	}

void DNS_Mgr::Event(EventHandlerPtr e, DNS_Mapping* dm, ListValPtr l1, ListValPtr l2)
	{
	if ( e )
		event_mgr.Enqueue(e, BuildMappingVal(dm), l1->ToSetVal(), l2->ToSetVal());
	}

void DNS_Mgr::Event(EventHandlerPtr e, DNS_Mapping* old_dm, DNS_Mapping* new_dm)
	{
	if ( e )
		event_mgr.Enqueue(e, BuildMappingVal(old_dm), BuildMappingVal(new_dm));
	}

ValPtr DNS_Mgr::BuildMappingVal(DNS_Mapping* dm)
	{
	auto r = make_intrusive<RecordVal>(dm_rec);

	r->AssignTime(0, dm->CreationTime());
	r->Assign(1, dm->ReqHost() ? dm->ReqHost() : "");
	r->Assign(2, make_intrusive<AddrVal>(dm->ReqAddr()));
	r->Assign(3, dm->Valid());

	auto h = dm->Host();
	r->Assign(4, h ? std::move(h) : make_intrusive<StringVal>("<none>"));
	r->Assign(5, dm->AddrsSet());

	return r;
	}

void DNS_Mgr::AddResult(DNS_Request* dr, struct hostent* h, uint32_t ttl)
	{
	DNS_Mapping* new_mapping;
	DNS_Mapping* prev_mapping;
	bool keep_prev = false;

	if ( dr->Host() )
		{
		new_mapping = new DNS_Mapping(dr->Host(), h, ttl);
		prev_mapping = nullptr;

		if ( dr->IsTxt() )
			{
			TextMap::iterator it = text_mappings.find(dr->Host());

			if ( it == text_mappings.end() )
				text_mappings[dr->Host()] = new_mapping;
			else
				{
				prev_mapping = it->second;
				it->second = new_mapping;
				}

			if ( new_mapping->Failed() && prev_mapping && prev_mapping->Valid() )
				{
				text_mappings[dr->Host()] = prev_mapping;
				keep_prev = true;
				}
			}
		else
			{
			HostMap::iterator it = host_mappings.find(dr->Host());
			if ( it == host_mappings.end() )
				{
				host_mappings[dr->Host()].first = new_mapping->Type() == AF_INET ? new_mapping
				                                                                 : nullptr;

				host_mappings[dr->Host()].second = new_mapping->Type() == AF_INET ? nullptr
				                                                                  : new_mapping;
				}
			else
				{
				if ( new_mapping->Type() == AF_INET )
					{
					prev_mapping = it->second.first;
					it->second.first = new_mapping;
					}
				else
					{
					prev_mapping = it->second.second;
					it->second.second = new_mapping;
					}
				}

			if ( new_mapping->Failed() && prev_mapping && prev_mapping->Valid() )
				{
				// Put previous, valid entry back - CompareMappings
				// will generate a corresponding warning.
				if ( prev_mapping->Type() == AF_INET )
					host_mappings[dr->Host()].first = prev_mapping;
				else
					host_mappings[dr->Host()].second = prev_mapping;

				keep_prev = true;
				}
			}
		}
	else
		{
		new_mapping = new DNS_Mapping(dr->Addr(), h, ttl);
		AddrMap::iterator it = addr_mappings.find(dr->Addr());
		prev_mapping = (it == addr_mappings.end()) ? 0 : it->second;
		addr_mappings[dr->Addr()] = new_mapping;

		if ( new_mapping->Failed() && prev_mapping && prev_mapping->Valid() )
			{
			addr_mappings[dr->Addr()] = prev_mapping;
			keep_prev = true;
			}
		}

	if ( prev_mapping && ! dr->IsTxt() )
		CompareMappings(prev_mapping, new_mapping);

	if ( keep_prev )
		delete new_mapping;
	else
		delete prev_mapping;
	}

void DNS_Mgr::CompareMappings(DNS_Mapping* prev_mapping, DNS_Mapping* new_mapping)
	{
	if ( prev_mapping->Failed() )
		{
		if ( new_mapping->Failed() )
			// Nothing changed.
			return;

		Event(dns_mapping_valid, new_mapping);
		return;
		}

	else if ( new_mapping->Failed() )
		{
		Event(dns_mapping_unverified, prev_mapping);
		return;
		}

	auto prev_s = prev_mapping->Host();
	auto new_s = new_mapping->Host();

	if ( prev_s || new_s )
		{
		if ( ! prev_s )
			Event(dns_mapping_new_name, new_mapping);
		else if ( ! new_s )
			Event(dns_mapping_lost_name, prev_mapping);
		else if ( ! Bstr_eq(new_s->AsString(), prev_s->AsString()) )
			Event(dns_mapping_name_changed, prev_mapping, new_mapping);
		}

	auto prev_a = prev_mapping->Addrs();
	auto new_a = new_mapping->Addrs();

	if ( ! prev_a || ! new_a )
		{
		reporter->InternalWarning("confused in DNS_Mgr::CompareMappings");
		return;
		}

	auto prev_delta = AddrListDelta(prev_a.get(), new_a.get());
	auto new_delta = AddrListDelta(new_a.get(), prev_a.get());

	if ( prev_delta->Length() > 0 || new_delta->Length() > 0 )
		Event(dns_mapping_altered, new_mapping, std::move(prev_delta), std::move(new_delta));
	}

ListValPtr DNS_Mgr::AddrListDelta(ListVal* al1, ListVal* al2)
	{
	auto delta = make_intrusive<ListVal>(TYPE_ADDR);

	for ( int i = 0; i < al1->Length(); ++i )
		{
		const IPAddr& al1_i = al1->Idx(i)->AsAddr();

		int j;
		for ( j = 0; j < al2->Length(); ++j )
			{
			const IPAddr& al2_j = al2->Idx(j)->AsAddr();
			if ( al1_i == al2_j )
				break;
			}

		if ( j >= al2->Length() )
			// Didn't find it.
			delta->Append(al1->Idx(i));
		}

	return delta;
	}

void DNS_Mgr::DumpAddrList(FILE* f, ListVal* al)
	{
	for ( int i = 0; i < al->Length(); ++i )
		{
		const IPAddr& al_i = al->Idx(i)->AsAddr();
		fprintf(f, "%s%s", i > 0 ? "," : "", al_i.AsString().c_str());
		}
	}

void DNS_Mgr::LoadCache(const std::string& path)
	{
	FILE* f = fopen(path.c_str(), "r");

	if ( ! f )
		return;

	// Loop until we find a mapping that doesn't initialize correctly.
	DNS_Mapping* m = new DNS_Mapping(f);
	for ( ; ! m->NoMapping() && ! m->InitFailed(); m = new DNS_Mapping(f) )
		{
		if ( m->ReqHost() )
			{
			if ( host_mappings.find(m->ReqHost()) == host_mappings.end() )
				{
				host_mappings[m->ReqHost()].first = 0;
				host_mappings[m->ReqHost()].second = 0;
				}
			if ( m->Type() == AF_INET )
				host_mappings[m->ReqHost()].first = m;
			else
				host_mappings[m->ReqHost()].second = m;
			}
		else
			{
			addr_mappings[m->ReqAddr()] = m;
			}
		}

	if ( ! m->NoMapping() )
		reporter->FatalError("DNS cache corrupted");

	delete m;
	fclose(f);
	}

bool DNS_Mgr::Save()
	{
	if ( cache_name.empty() )
		return false;

	FILE* f = fopen(cache_name.c_str(), "w");

	if ( ! f )
		return false;

	Save(f, host_mappings);
	Save(f, addr_mappings);
	// Save(f, text_mappings); // We don't save the TXT mappings (yet?).

	fclose(f);

	return true;
	}

void DNS_Mgr::Save(FILE* f, const AddrMap& m)
	{
	for ( AddrMap::const_iterator it = m.begin(); it != m.end(); ++it )
		{
		if ( it->second )
			it->second->Save(f);
		}
	}

void DNS_Mgr::Save(FILE* f, const HostMap& m)
	{
	for ( HostMap::const_iterator it = m.begin(); it != m.end(); ++it )
		{
		if ( it->second.first )
			it->second.first->Save(f);

		if ( it->second.second )
			it->second.second->Save(f);
		}
	}

TableValPtr DNS_Mgr::LookupNameInCache(const std::string& name, bool cleanup_expired,
                                       bool check_failed)
	{
	HostMap::iterator it = host_mappings.find(name);
	if ( it == host_mappings.end() )
		{
		it = host_mappings.begin();
		return nullptr;
		}

	DNS_Mapping* d4 = it->second.first;
	DNS_Mapping* d6 = it->second.second;

	if ( ! d4 || d4->names.empty() || ! d6 || d6->names.empty() )
		return nullptr;

	if ( cleanup_expired && (d4->Expired() || d6->Expired()) )
		{
		host_mappings.erase(it);
		delete d4;
		delete d6;
		return nullptr;
		}

	if ( check_failed && ((d4 && d4->Failed()) || (d6 && d6->Failed())) )
		{
		reporter->Warning("no such host: %s", name.c_str());
		return empty_addr_set();
		}

	auto tv4 = d4->AddrsSet();
	auto tv6 = d6->AddrsSet();
	tv4->AddTo(tv6.get(), false);
	return tv6;
	}

StringValPtr DNS_Mgr::LookupAddrInCache(const IPAddr& addr, bool cleanup_expired, bool check_failed)
	{
	AddrMap::iterator it = addr_mappings.find(addr);

	if ( it == addr_mappings.end() )
		return nullptr;

	DNS_Mapping* d = it->second;

	if ( cleanup_expired && d->Expired() )
		{
		addr_mappings.erase(it);
		delete d;
		return nullptr;
		}
	else if ( check_failed && d->Failed() )
		{
		std::string s(addr);
		reporter->Warning("can't resolve IP address: %s", s.c_str());
		return make_intrusive<StringVal>(s);
		}

	// TODO: this used to return "<\?\?\?>" if the list of hosts was empty. Why?
	return d->Host();
	}

StringValPtr DNS_Mgr::LookupTextInCache(const std::string& name, bool cleanup_expired)
	{
	TextMap::iterator it = text_mappings.find(name);
	if ( it == text_mappings.end() )
		return nullptr;

	DNS_Mapping* d = it->second;

	if ( cleanup_expired && d->Expired() )
		{
		text_mappings.erase(it);
		delete d;
		return nullptr;
		}

	// TODO: this used to return "<\?\?\?>" if the list of hosts was empty. Why?
	return d->Host();
	}

void DNS_Mgr::IssueAsyncRequests()
	{
	while ( ! asyncs_queued.empty() && asyncs_pending < MAX_PENDING_REQUESTS )
		{
		AsyncRequest* req = asyncs_queued.front();
		asyncs_queued.pop_front();

		++num_requests;
		req->time = util::current_time();

		if ( req->IsAddrReq() )
			{
			auto* m_req = new DNS_Request(req->host);
			m_req->MakeRequest(channel);
			}
		else if ( req->is_txt )
			{
			auto* m_req = new DNS_Request(req->name.c_str(), AF_UNSPEC, T_TXT);
			m_req->MakeRequest(channel);
			}
		else
			{
			// If only one request type succeeds, don't consider it a failure.
			auto* m_req4 = new DNS_Request(req->name.c_str(), AF_INET, T_A);
			m_req4->MakeRequest(channel);
			auto* m_req6 = new DNS_Request(req->name.c_str(), AF_INET6, T_AAAA);
			m_req6->MakeRequest(channel);
			}

		asyncs_timeouts.push(req);

		++asyncs_pending;
		}
	}

void DNS_Mgr::CheckAsyncHostRequest(const char* host, bool timeout)
	{
	// Note that this code is a mirror of that for CheckAsyncAddrRequest.

	AsyncRequestNameMap::iterator i = asyncs_names.find(host);

	if ( i != asyncs_names.end() )
		{
		if ( auto addrs = LookupNameInCache(host, true, false) )
			{
			++successful;
			i->second->Resolved(addrs);
			}
		else if ( timeout )
			{
			++failed;
			i->second->Timeout();
			}
		else
			return;

		asyncs_names.erase(i);
		--asyncs_pending;

		// Don't delete the request.  That will be done once it
		// eventually times out.
		}
	}

void DNS_Mgr::CheckAsyncAddrRequest(const IPAddr& addr, bool timeout)
	{
	// Note that this code is a mirror of that for CheckAsyncHostRequest.

	// In the following, if it's not in the respective map anymore, we've
	// already finished it earlier and don't have anything to do.
	AsyncRequestAddrMap::iterator i = asyncs_addrs.find(addr);

	if ( i != asyncs_addrs.end() )
		{
		if ( auto name = LookupAddrInCache(addr, true, false) )
			{
			++successful;
			i->second->Resolved(name->CheckString());
			}
		else if ( timeout )
			{
			++failed;
			i->second->Timeout();
			}
		else
			return;

		asyncs_addrs.erase(i);
		--asyncs_pending;

		// Don't delete the request.  That will be done once it
		// eventually times out.
		}
	}

void DNS_Mgr::CheckAsyncTextRequest(const char* host, bool timeout)
	{
	// Note that this code is a mirror of that for CheckAsyncAddrRequest.

	AsyncRequestTextMap::iterator i = asyncs_texts.find(host);
	if ( i != asyncs_texts.end() )
		{
		if ( auto name = LookupTextInCache(host, true) )
			{
			++successful;
			i->second->Resolved(name->CheckString());
			}
		else if ( timeout )
			{
			AsyncRequestTextMap::iterator it = asyncs_texts.begin();
			++failed;
			i->second->Timeout();
			}
		else
			return;

		asyncs_texts.erase(i);
		--asyncs_pending;

		// Don't delete the request.  That will be done once it
		// eventually times out.
		}
	}

void DNS_Mgr::Flush()
	{
	Process();

	HostMap::iterator it;
	for ( it = host_mappings.begin(); it != host_mappings.end(); ++it )
		{
		delete it->second.first;
		delete it->second.second;
		}

	for ( AddrMap::iterator it2 = addr_mappings.begin(); it2 != addr_mappings.end(); ++it2 )
		delete it2->second;

	for ( TextMap::iterator it3 = text_mappings.begin(); it3 != text_mappings.end(); ++it3 )
		delete it3->second;

	host_mappings.clear();
	addr_mappings.clear();
	text_mappings.clear();
	}

double DNS_Mgr::GetNextTimeout()
	{
	if ( asyncs_timeouts.empty() )
		return -1;

	return run_state::network_time + DNS_TIMEOUT;
	}

void DNS_Mgr::Process()
	{
	while ( ! asyncs_timeouts.empty() )
		{
		AsyncRequest* req = asyncs_timeouts.top();

		if ( req->time + DNS_TIMEOUT > util::current_time() && ! run_state::terminating )
			break;

		if ( ! req->processed )
			{
			if ( req->IsAddrReq() )
				CheckAsyncAddrRequest(req->host, true);
			else if ( req->is_txt )
				CheckAsyncTextRequest(req->name.c_str(), true);
			else
				CheckAsyncHostRequest(req->name.c_str(), true);
			}

		asyncs_timeouts.pop();
		delete req;
		}

	Resolve();

	// TODO: what does the rest below do?
	/*
	char err[NB_DNS_ERRSIZE];
	struct nb_dns_result r;

	int status = nb_dns_activity(nb_dns, &r, err);

	if ( status < 0 )
	    reporter->Warning("NB-DNS error in DNS_Mgr::Process (%s)", err);

	else if ( status > 0 )
	    {
	    DNS_Request* dr = (DNS_Request*)r.cookie;

	    bool do_host_timeout = true;
	    if ( dr->Host() && host_mappings.find(dr->Host()) == host_mappings.end() )
	        // Don't timeout when this is the first result in an expected pair
	        // (one result each for A and AAAA queries).
	        do_host_timeout = false;

	    if ( dr->RequestPending() )
	        {
	        AddResult(dr, &r);
	        dr->RequestDone();
	        }

	    if ( ! dr->Host() )
	        CheckAsyncAddrRequest(dr->Addr(), true);
	    else if ( dr->IsTxt() )
	        CheckAsyncTextRequest(dr->Host(), do_host_timeout);
	    else
	        CheckAsyncHostRequest(dr->Host(), do_host_timeout);

	    IssueAsyncRequests();

	    delete dr;
	    }
	*/
	}

void DNS_Mgr::GetStats(Stats* stats)
	{
	// TODO: can this use the telemetry framework?
	stats->requests = num_requests;
	stats->successful = successful;
	stats->failed = failed;
	stats->pending = asyncs_pending;
	stats->cached_hosts = host_mappings.size();
	stats->cached_addresses = addr_mappings.size();
	stats->cached_texts = text_mappings.size();
	}

TableValPtr DNS_Mgr::empty_addr_set()
	{
	// TODO: can this be returned staticly as well? Does the result get used in a way
	// that would modify the same value being returned repeatedly?
	auto addr_t = base_type(TYPE_ADDR);
	auto set_index = make_intrusive<TypeList>(addr_t);
	set_index->Append(std::move(addr_t));
	auto s = make_intrusive<SetType>(std::move(set_index), nullptr);
	return make_intrusive<TableVal>(std::move(s));
	}

	} // namespace zeek::detail
