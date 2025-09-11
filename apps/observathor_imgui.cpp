#ifdef _WIN32
#define NOMINMAX
#endif
#include "observathor/core/proxy/ProxyServer.h"
#include "observathor/core/proxy/TransactionRingBufferObserver.h"
#include "observathor/core/proxy/TransactionFileStore.h"
#include "observathor/core/proxy/TransactionLogObserver.h"
#include "observathor/core/util/Logger.h"
#include <imgui.h>
#include <backends/imgui_impl_glfw.h>
#include <backends/imgui_impl_opengl2.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <atomic>
#include <GLFW/glfw3.h>
#include <chrono>
#include <fstream>
#include <sstream>

using namespace observathor::core::proxy;
using observathor::core::util::log_info;

static uint16_t parse_port(const char* s){ if(!s) return 8888; int v=std::atoi(s); if(v<=0||v>65535) return 8888; return static_cast<uint16_t>(v); }

static std::string make_hex(const std::string& data) {
    std::ostringstream oss; oss.setf(std::ios::hex, std::ios::basefield); oss.fill('0');
    const unsigned perLine = 16;
    for (size_t i=0;i<data.size(); i+=perLine) {
        oss<<""; // no offset for now
        size_t lineEnd = std::min(data.size(), i+perLine);
        for(size_t j=i;j<lineEnd;++j){ unsigned char c = static_cast<unsigned char>(data[j]); oss.width(2); oss<< (int)c << ' '; }
        oss<<' '; // gap
        for(size_t j=i;j<lineEnd;++j){ unsigned char c = static_cast<unsigned char>(data[j]); oss<< (c>=32&&c<127?char(c):'.'); }
        if(lineEnd!=data.size()) oss<<"\n";
    }
    return oss.str();
}

static std::string read_file_preview(const std::string& path, size_t maxBytes, bool& truncated){
    truncated=false; std::ifstream f(path, std::ios::binary); if(!f) return std::string();
    std::string out; out.resize(maxBytes);
    f.read(out.data(), static_cast<std::streamsize>(maxBytes)); std::streamsize got = f.gcount(); out.resize(static_cast<size_t>(got));
    if(f.peek()!=std::char_traits<char>::eof()) truncated=true;
    return out;
}

int main(int argc, char** argv){
    uint16_t port = 8888; size_t cap_bytes = 4096; const char* file_path = nullptr; bool dark=true; 
    bool enable_mitm=false; const char* ca_cert_path=nullptr; const char* ca_key_path=nullptr; const char* mitm_allow=nullptr; const char* mitm_deny=nullptr;
    for(int i=1;i<argc;++i){
        if(std::strcmp(argv[i],"--port")==0 && i+1<argc) port=parse_port(argv[++i]);
        else if(std::strcmp(argv[i],"--capture-bytes")==0 && i+1<argc) cap_bytes = static_cast<size_t>(std::atoll(argv[++i]));
        else if(std::strcmp(argv[i],"--capture-file")==0 && i+1<argc) file_path = argv[++i];
    else if(std::strcmp(argv[i],"--enable-mitm")==0) enable_mitm=true;
    else if(std::strcmp(argv[i],"--mitm-allow")==0 && i+1<argc) mitm_allow = argv[++i];
    else if(std::strcmp(argv[i],"--mitm-deny")==0 && i+1<argc) mitm_deny = argv[++i];
        else if(std::strcmp(argv[i],"--ca-cert")==0 && i+1<argc) ca_cert_path=argv[++i];
        else if(std::strcmp(argv[i],"--ca-key")==0 && i+1<argc) ca_key_path=argv[++i];
        else if(std::strcmp(argv[i],"--light")==0) dark=false;
        else if(std::strcmp(argv[i],"--log-level")==0 && i+1<argc){ ++i; /* ignore for now */ }
    }

    if(!glfwInit()){ std::fprintf(stderr,"glfw init failed\n"); return 1; }
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR,3); glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR,0);
#ifdef __APPLE__
    glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GL_TRUE);
#endif
    GLFWwindow* window = glfwCreateWindow(1280,720,"Observathor UI",nullptr,nullptr);
    if(!window){ std::fprintf(stderr,"window create failed\n"); return 1; }
    glfwMakeContextCurrent(window); glfwSwapInterval(1);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;
    if(dark) ImGui::StyleColorsDark(); else ImGui::StyleColorsLight();
    ImGui_ImplGlfw_InitForOpenGL(window,true);
    ImGui_ImplOpenGL2_Init();

    Config cfg; cfg.capture_bytes_limit = cap_bytes; if(file_path) cfg.capture_file_path = file_path; if(enable_mitm) cfg.enableTlsMitm=true; if(ca_cert_path) cfg.caCertPath=ca_cert_path; if(ca_key_path) cfg.caKeyPath=ca_key_path; cfg.mitmAllowList = mitm_allow; cfg.mitmDenyList = mitm_deny;
    ProxyServer server(port, cfg);
    auto log_obs = std::make_shared<TransactionLogObserver>(); server.dispatcher().add(log_obs);
    auto ring = make_ring_buffer(server.dispatcher(), 2000);
    std::shared_ptr<TransactionFileStore> file_store; if(file_path) file_store = make_file_store(server.dispatcher(), file_path);
    server.start();

    static uint64_t selected_id = 0;
    static bool showHexReq = false, showHexResp = false;
    static auto appStart = std::chrono::steady_clock::now();

    bool showTlsWindow = true; // show by default first launch
    // Runtime editable copies of allow/deny
    static char allowBuf[512] = {0}; static char denyBuf[512] = {0};
    if(mitm_allow) { std::strncpy(allowBuf, mitm_allow, sizeof(allowBuf)-1); }
    if(mitm_deny) { std::strncpy(denyBuf, mitm_deny, sizeof(denyBuf)-1); }
    while(!glfwWindowShouldClose(window)){
        glfwPollEvents();
        ImGui_ImplOpenGL2_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        auto snapshot = ring->snapshot();

        ImGui::SetNextWindowPos(ImVec2(0,0), ImGuiCond_Always);
        ImGui::SetNextWindowSize(ImVec2((float)io.DisplaySize.x,(float)io.DisplaySize.y), ImGuiCond_Always);
        ImGui::Begin("Observathor", nullptr, ImGuiWindowFlags_NoTitleBar|ImGuiWindowFlags_NoResize|ImGuiWindowFlags_NoMove|ImGuiWindowFlags_MenuBar);
        if(ImGui::BeginMenuBar()){
            if(ImGui::BeginMenu("View")){
                ImGui::MenuItem("Hex Request Body", nullptr, &showHexReq);
                ImGui::MenuItem("Hex Response Body", nullptr, &showHexResp);
                ImGui::EndMenu();
            }
            if(ImGui::BeginMenu("TLS")){
                ImGui::MenuItem("Certificate & MITM", nullptr, &showTlsWindow);
                ImGui::EndMenu();
            }
            ImGui::EndMenuBar();
        }
        ImGui::Text("Port %u | %zu transactions", port, snapshot.size()); ImGui::SameLine();
        ImGui::TextDisabled(cfg.enableTlsMitm?"MITM ON":"MITM OFF");
        ImGui::Separator();
        const float leftWidth = ImGui::GetContentRegionAvail().x * 0.45f;
        ImGui::BeginChild("left_pane", ImVec2(leftWidth, 0), true);
        if(ImGui::BeginTable("tx_table", 8, ImGuiTableFlags_RowBg|ImGuiTableFlags_ScrollY|ImGuiTableFlags_Resizable|ImGuiTableFlags_SizingStretchProp)){
            ImGui::TableSetupScrollFreeze(0,1);
            ImGui::TableSetupColumn("Time");
            ImGui::TableSetupColumn("Method");
            ImGui::TableSetupColumn("Target");
            ImGui::TableSetupColumn("Status");
            ImGui::TableSetupColumn("In");
            ImGui::TableSetupColumn("Out");
            ImGui::TableSetupColumn("Resp Sz");
            ImGui::TableSetupColumn("TLS");
            ImGui::TableHeadersRow();
            for(auto & t : snapshot){
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                // Format local time HH:MM:SS.mmm
                std::time_t tt = std::chrono::system_clock::to_time_t(t.wallTime);
                std::tm local_tm{};
#ifdef _WIN32
                localtime_s(&local_tm, &tt);
#else
                localtime_r(&tt, &local_tm);
#endif
                auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t.wallTime.time_since_epoch()) % 1000;
                char timeBuf[32]; std::snprintf(timeBuf, sizeof(timeBuf), "%02d:%02d:%02d.%03lld", local_tm.tm_hour, local_tm.tm_min, local_tm.tm_sec, (long long)ms.count());
                ImGui::TextUnformatted(timeBuf);
                std::string method, target; {
                    auto pos1 = t.requestLine.find(' ');
                    if(pos1!=std::string::npos){ method = t.requestLine.substr(0,pos1); auto pos2 = t.requestLine.find(' ', pos1+1); if(pos2!=std::string::npos) target = t.requestLine.substr(pos1+1, pos2-pos1-1); }
                }
                bool is_selected = (t.id == selected_id);
                ImGui::TableSetColumnIndex(1);
                ImGui::PushID((int)t.id);
                if(ImGui::Selectable(method.empty()?"?":method.c_str(), is_selected, ImGuiSelectableFlags_SpanAllColumns)) selected_id = t.id;
                ImGui::PopID();
                ImGui::TableSetColumnIndex(2); ImGui::TextUnformatted(target.c_str());
                ImGui::TableSetColumnIndex(3); ImGui::TextUnformatted(t.responseStatusLine.c_str());
                ImGui::TableSetColumnIndex(4); ImGui::Text("%llu", (unsigned long long)t.bytesIn);
                ImGui::TableSetColumnIndex(5); ImGui::Text("%llu", (unsigned long long)t.bytesOut);
                ImGui::TableSetColumnIndex(6); ImGui::Text("%zu", t.responseBody.size());
                ImGui::TableSetColumnIndex(7);
                if(!t.mitmOutcome.empty()){
                    const char* label = t.mitmOutcome=="intercepted"? "MITM" : (t.mitmOutcome=="tunneled"? "TUN" : t.mitmOutcome.c_str());
                    ImGui::TextUnformatted(label);
                    if(ImGui::IsItemHovered()) ImGui::SetTooltip("%s", t.mitmOutcome.c_str());
                } else if (t.tlsMitmIntercepted) { ImGui::TextUnformatted("MITM"); }
            }
            ImGui::EndTable();
        }
        ImGui::EndChild();

        ImGui::SameLine();
        ImGui::BeginChild("right_pane", ImVec2(0,0), true);
        if(selected_id){
            const Transaction* sel=nullptr; for(auto & t : snapshot){ if(t.id==selected_id){ sel=&t; break; }}
            if(sel){
                auto sinceStart = std::chrono::duration_cast<std::chrono::milliseconds>(sel->startTime - appStart).count();
                {
                    std::time_t tt = std::chrono::system_clock::to_time_t(sel->wallTime);
                    std::tm local_tm{};
#ifdef _WIN32
                    localtime_s(&local_tm, &tt);
#else
                    localtime_r(&tt, &local_tm);
#endif
                    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(sel->wallTime.time_since_epoch()) % 1000;
                    char timeBuf[64]; std::snprintf(timeBuf, sizeof(timeBuf), "%04d-%02d-%02d %02d:%02d:%02d.%03lld", local_tm.tm_year+1900, local_tm.tm_mon+1, local_tm.tm_mday, local_tm.tm_hour, local_tm.tm_min, local_tm.tm_sec, (long long)ms.count());
                    ImGui::Text("Time: %s", timeBuf);
                    ImGui::SameLine(); if(ImGui::SmallButton("Copy Time")){ ImGui::SetClipboardText(timeBuf); }
                    ImGui::SameLine(); ImGui::TextDisabled("ID %llu", (unsigned long long)sel->id);
                    ImGui::SameLine(); if(ImGui::SmallButton("Copy ID")){ ImGui::SetClipboardText(std::to_string(sel->id).c_str()); }
                }
                ImGui::Separator();
                ImGui::Text("Timestamp: %lld ms", (long long)sinceStart);
                ImGui::Separator();
                ImGui::Text("Request Line: %s", sel->requestLine.c_str());
                if(!sel->requestHeaders.empty()){
                    ImGui::Separator();
                    ImGui::TextUnformatted("Request Headers"); ImGui::SameLine(); if(ImGui::SmallButton("Copy##reqhdr")){ ImGui::SetClipboardText(sel->requestHeaders.c_str()); }
                    ImGui::BeginChild("req_hdrs", ImVec2(0,100), true, ImGuiWindowFlags_HorizontalScrollbar); ImGui::TextUnformatted(sel->requestHeaders.c_str()); ImGui::EndChild();
                }
                // Request Body
                if(sel->requestBodyInFile || !sel->requestBody.empty()){
                    bool truncated=false; std::string body = sel->requestBodyInFile? read_file_preview(sel->requestBodyPath, 32*1024, truncated) : sel->requestBody;
                    ImGui::Separator();
                    ImGui::Text("Request Body (%s, %zu bytes%s)", sel->requestBodyInFile?"file":"mem", sel->requestBodyInFile? (size_t)body.size(): sel->requestBody.size(), truncated?" (truncated preview)":"");
                    if(ImGui::SmallButton(showHexReq?"Show Raw##req":"Show Hex##req")) showHexReq=!showHexReq; ImGui::SameLine(); if(ImGui::SmallButton("Copy##reqbody")){ ImGui::SetClipboardText(body.c_str()); } ImGui::SameLine(); if(ImGui::SmallButton("Save##reqbody")){ /* TODO save request body */ }
                    std::string display = showHexReq? make_hex(body) : body;
                    ImGui::BeginChild("req_body", ImVec2(0,120), true, ImGuiWindowFlags_HorizontalScrollbar); ImGui::TextUnformatted(display.c_str()); ImGui::EndChild();
                }
                if(!sel->responseStatusLine.empty()){
                    ImGui::Separator(); ImGui::Text("Response Status: %s", sel->responseStatusLine.c_str()); ImGui::SameLine(); if(ImGui::SmallButton("Copy Status")){ ImGui::SetClipboardText(sel->responseStatusLine.c_str()); }
                }
                if(!sel->responseHeaders.empty()){
                    ImGui::Separator(); ImGui::TextUnformatted("Response Headers"); ImGui::SameLine(); if(ImGui::SmallButton("Copy##resphdr")){ ImGui::SetClipboardText(sel->responseHeaders.c_str()); }
                    ImGui::BeginChild("resp_hdrs", ImVec2(0,100), true, ImGuiWindowFlags_HorizontalScrollbar); ImGui::TextUnformatted(sel->responseHeaders.c_str()); ImGui::EndChild();
                }
                if(sel->responseBodyInFile || !sel->responseBody.empty()){
                    bool truncated=false; std::string body = sel->responseBodyInFile? read_file_preview(sel->responseBodyPath, 64*1024, truncated) : sel->responseBody;
                    ImGui::Separator();
                    ImGui::Text("Response Body (%s, %zu bytes%s)", sel->responseBodyInFile?"file":"mem", sel->responseBodyInFile? (size_t)body.size(): sel->responseBody.size(), truncated?" (truncated preview)":"");
                    if(ImGui::SmallButton(showHexResp?"Show Raw##resp":"Show Hex##resp")) showHexResp=!showHexResp; ImGui::SameLine(); if(ImGui::SmallButton("Copy##respbody")){ ImGui::SetClipboardText(body.c_str()); } ImGui::SameLine(); if(ImGui::SmallButton("Save##respbody")){ /* TODO save response body */ }
                    std::string display = showHexResp? make_hex(body) : body;
                    ImGui::BeginChild("resp_body", ImVec2(0,160), true, ImGuiWindowFlags_HorizontalScrollbar); ImGui::TextUnformatted(display.c_str()); ImGui::EndChild();
                }
            }
        }
        ImGui::EndChild();
        ImGui::End();

        // Separate TLS window
        if (showTlsWindow) {
            if(ImGui::Begin("TLS / Certificate", &showTlsWindow)) {
                auto tctx = server.tls_context();
#ifdef OBSERVATHOR_HAVE_OPENSSL
                std::string fp = tctx? tctx->ca_fingerprint_sha256() : std::string();
                ImGui::Text("Root CA Fingerprint (SHA-256): %s", fp.empty()?"(unavailable)":fp.c_str());
                ImGui::SameLine(); if(!fp.empty() && ImGui::SmallButton("Copy##fp")) ImGui::SetClipboardText(fp.c_str());
                if (tctx) {
                    if (ImGui::SmallButton("Export PEM")) { auto pem = tctx->export_ca_pem(); if(!pem.empty()){ std::ofstream f("observathor_root_ca.pem", std::ios::binary); f.write(pem.data(), (std::streamsize)pem.size()); } }
                    ImGui::SameLine(); if (ImGui::SmallButton("Export DER")) { auto der = tctx->export_ca_der(); if(!der.empty()){ std::ofstream f("observathor_root_ca.der", std::ios::binary); f.write(der.data(), (std::streamsize)der.size()); } }
                    static bool showPem=false; ImGui::SameLine(); ImGui::Checkbox("Show PEM", &showPem);
                    if (showPem) {
                        auto pem = tctx->export_ca_pem();
                        if(!pem.empty()) { ImGui::InputTextMultiline("##pem", pem.data(), pem.size()+1, ImVec2(-FLT_MIN, 200), ImGuiInputTextFlags_ReadOnly); }
                    }
                }
                ImGui::Separator();
                // Runtime MITM toggle
                bool mitmEnabled = server.mitm_policy().is_enabled();
                if(ImGui::Checkbox("Enable MITM Interception", &mitmEnabled)) {
                    server.mitm_policy().set_enabled(mitmEnabled);
                }
                ImGui::TextDisabled("Allow / Deny host globs (comma separated). Empty allow => all hosts unless denied.");
                if(ImGui::InputText("Allow List", allowBuf, IM_ARRAYSIZE(allowBuf))) {
                    // live update when user modifies (on each change parse)
                }
                if(ImGui::InputText("Deny List", denyBuf, IM_ARRAYSIZE(denyBuf))) {
                }
                if(ImGui::SmallButton("Apply Host Filters")) {
                    auto parseList=[&](const char* s){ std::vector<std::string> out; if(!s) return out; std::string cur; for(const char* p=s; *p; ++p){ if(*p==','){ if(!cur.empty()) { out.push_back(cur); cur.clear(); } } else if(!(*p==' ' && cur.empty())) cur.push_back(*p); } if(!cur.empty()) out.push_back(cur); return out; };
                    server.mitm_policy().set_lists(parseList(allowBuf[0]?allowBuf:nullptr), parseList(denyBuf[0]?denyBuf:nullptr));
                }
                ImGui::Separator();
                ImGui::TextWrapped("Install this root CA in your system or device trust store, then enable MITM. Use allow/deny filters for selective interception.");
#else
                ImGui::TextUnformatted("TLS not compiled in");
#endif
            }
            ImGui::End();
        }

        ImGui::Render();
        int display_w, display_h; glfwGetFramebufferSize(window,&display_w,&display_h);
        glViewport(0,0,display_w,display_h); glScissor(0,0,display_w,display_h);
        glClearColor(0.1f,0.1f,0.12f,1.f); glClear(0x00004000);
        ImGui_ImplOpenGL2_RenderDrawData(ImGui::GetDrawData());
        glfwSwapBuffers(window);
    }

    server.stop();
    ImGui_ImplOpenGL2_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    glfwDestroyWindow(window); glfwTerminate();
    return 0;
}
