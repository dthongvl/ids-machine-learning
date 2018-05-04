//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------
// dpx.cc author Russ Combs <rcombs@sourcefire.com>
// snort -c /usr/local/snort/etc/snort/snort.lua --plugin-path /usr/local/snort/lib/snort_extra/ -r ~/Downloads/http.cap
#include <iostream>
#include <curl/curl.h>
#include "packet_generated.h"
#include "detection/detection_engine.h"
#include "events/event_queue.h"
#include "framework/inspector.h"
#include "framework/module.h"
#include "log/messages.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"

using namespace snort;

#define DPX_GID 256
#define DPX_SID 1

static const char *s_name = "dpx";
static const char *s_help = "dynamic inspector example";

static THREAD_LOCAL ProfileStats dpxPerfStats;

static THREAD_LOCAL SimpleStats dpxstats;

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    ((std::string *)userp)->append((char *)contents, size * nmemb);
    return size * nmemb;
}

class Dpx : public Inspector
{
  public:
    Dpx(uint16_t port, uint16_t max);

    void show(SnortConfig *) override;

    void eval(Packet *) override;

  private:
    uint16_t port;
    uint16_t max;
};

Dpx::Dpx(uint16_t p, uint16_t m)
{
    port = p;
    max = m;
}

void Dpx::show(SnortConfig *)
{
    LogMessage("%s config:\n", s_name);
    LogMessage("    port = %d\n", port);
    LogMessage("    max = %d\n", max);
}

void Dpx::eval(Packet *p)
{
    flatbuffers::FlatBufferBuilder builder(1024);
    auto protocolType = builder.CreateString("tcp");
    auto service = builder.CreateString("private");
    auto flag = builder.CreateString("REJ");

    kmeans::PacketBuilder packetBuilder(builder);
    packetBuilder.add_duration(0);
    packetBuilder.add_protocol_type(protocolType);
    packetBuilder.add_service(service);
    packetBuilder.add_flag(flag);
    packetBuilder.add_src_bytes(0);
    packetBuilder.add_dst_bytes(0);
    packetBuilder.add_land(0);
    packetBuilder.add_wrong_fragment(0);
    packetBuilder.add_urgent(0);
    packetBuilder.add_hot(0);
    packetBuilder.add_num_failed_logins(0);
    packetBuilder.add_logged_in(0);
    packetBuilder.add_num_compromised(0);
    packetBuilder.add_root_shell(0);
    packetBuilder.add_su_attempted(0);
    packetBuilder.add_num_root(0);
    packetBuilder.add_num_file_creations(0);
    packetBuilder.add_num_shells(0);
    packetBuilder.add_num_access_files(0);
    packetBuilder.add_num_outbound_cmds(0);
    packetBuilder.add_is_host_login(0);
    packetBuilder.add_is_guest_login(0);
    packetBuilder.add_count(229);
    packetBuilder.add_srv_count(10);
    packetBuilder.add_serror_rate(0);
    packetBuilder.add_srv_serror_rate(0);
    packetBuilder.add_rerror_rate(1);
    packetBuilder.add_srv_rerror_rate(1);
    packetBuilder.add_same_srv_rate(0.04);
    packetBuilder.add_diff_srv_rate(0.06);
    packetBuilder.add_srv_diff_host_rate(0);
    packetBuilder.add_dst_host_count(255);
    packetBuilder.add_dst_host_srv_count(10);
    packetBuilder.add_dst_host_same_srv_rate(0.04);
    packetBuilder.add_dst_host_diff_srv_rate(0.06);
    packetBuilder.add_dst_host_same_src_port_rate(0);
    packetBuilder.add_dst_host_srv_diff_host_rate(0);
    packetBuilder.add_dst_host_serror_rate(0);
    packetBuilder.add_dst_host_srv_serror_rate(0);
    packetBuilder.add_dst_host_rerror_rate(1);
    packetBuilder.add_dst_host_srv_rerror_rate(1);
    auto orc = packetBuilder.Finish();
    builder.Finish(orc);
    uint8_t *buf = builder.GetBufferPointer();
    int size = builder.GetSize();

    std::string readBuffer;

    curl_global_init(CURL_GLOBAL_ALL);
    CURL *ctx = curl_easy_init();
    curl_easy_setopt(ctx, CURLOPT_URL, "http://localhost:5000/predict");

    curl_easy_setopt(ctx, CURLOPT_POST, 1);
    curl_easy_setopt(ctx, CURLOPT_POSTFIELDS, buf);
    curl_easy_setopt(ctx, CURLOPT_POSTFIELDSIZE, size);
    curl_easy_setopt(ctx, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(ctx, CURLOPT_WRITEDATA, &readBuffer);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/octet-stream");
    curl_easy_setopt(ctx, CURLOPT_HTTPHEADER, headers);

    CURLcode ret = curl_easy_perform(ctx);
    if (ret != CURLE_OK)
        fprintf(stderr, "curl_easy_perform() failed: %s\n",
                curl_easy_strerror(ret));

    curl_slist_free_all(headers);
    curl_easy_cleanup(ctx);

    std::cout << readBuffer << std::endl;
    // precondition - what we registered for
    //    assert(p->is_udp());
    //
    //    if ( p->ptrs.dp == port && p->dsize > max )
    //        DetectionEngine::queue_event(DPX_GID, DPX_SID);

    ++dpxstats.total_packets;
}

//-------------------------------------------------------------------------
// module stuff
//-------------------------------------------------------------------------

static const Parameter dpx_params[] =
    {
        {"port", Parameter::PT_PORT, nullptr, nullptr,
         "port to check"},

        {"max", Parameter::PT_INT, "0:65535", "0",
         "maximum payload before alert"},

        {nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr}};

static const RuleMap dpx_rules[] =
    {
        {DPX_SID, "too much data sent to port"},
        {0, nullptr}};

class DpxModule : public Module
{
  public:
    DpxModule() : Module(s_name, s_help, dpx_params) {}

    unsigned get_gid() const override { return DPX_GID; }

    const RuleMap *get_rules() const override { return dpx_rules; }

    const PegInfo *get_pegs() const override { return simple_pegs; }

    PegCount *get_counts() const override { return (PegCount *)&dpxstats; }

    ProfileStats *get_profile() const override { return &dpxPerfStats; }

    bool set(const char *, Value &v, SnortConfig *) override;

    Usage get_usage() const override { return INSPECT; }

  public:
    uint16_t port;
    uint16_t max;
};

bool DpxModule::set(const char *, Value &v, SnortConfig *)
{
    if (v.is("port"))
        port = v.get_long();

    else if (v.is("max"))
        max = v.get_long();

    else
        return false;

    return true;
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module *mod_ctor() { return new DpxModule; }

static void mod_dtor(Module *m) { delete m; }

static Inspector *dpx_ctor(Module *m)
{
    DpxModule *mod = (DpxModule *)m;
    return new Dpx(mod->port, mod->max);
}

static void dpx_dtor(Inspector *p)
{
    delete p;
}

static const InspectApi dpx_api{
    {PT_INSPECTOR,
     sizeof(InspectApi),
     INSAPI_VERSION,
     0,
     API_RESERVED,
     API_OPTIONS,
     s_name,
     s_help,
     mod_ctor,
     mod_dtor},
    IT_PACKET,
    PROTO_BIT__ALL,
    nullptr, // buffers
    nullptr, // service
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    dpx_ctor,
    dpx_dtor,
    nullptr, // ssn
    nullptr  // reset
};

SO_PUBLIC const BaseApi *snort_plugins[] =
    {
        &dpx_api.base,
        nullptr};
