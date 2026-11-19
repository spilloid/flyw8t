// The MSVC build imports the installed Windows RDP control's own type library.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <ocidl.h>
#include <wrl/client.h>
#import <mstscax.dll> raw_interfaces_only no_implementation named_guids rename_namespace("Rdp")
#include <algorithm>
#include <array>
#include <cwchar>
#include <memory>
#include <new>

using Microsoft::WRL::ComPtr;

struct Notice {
    LONG kind = 0;
    LONG reason = 0;
    LONG extended = 0;
    wchar_t detail[512]{};
};

// The ATL host registers window procedures. Keep one trusted system DLL loaded
// throughout the process, including between successive session windows.
static HMODULE atl_module() {
    static HMODULE module = []() -> HMODULE {
        wchar_t path[MAX_PATH];
        const UINT n = GetSystemDirectoryW(path, MAX_PATH);
        if (!n || n + 9 >= MAX_PATH) return nullptr;
        wcscat_s(path, L"\\atl.dll");
        return LoadLibraryExW(path, nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    }();
    return module;
}

struct Session;
struct EventSink final : IDispatch {
    LONG refs = 1;
    Session* session = nullptr;
    std::array<DISPID, 6> events{};

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** target) override {
        if (!target) return E_POINTER;
        *target = nullptr;
        if (iid != IID_IUnknown && iid != IID_IDispatch && iid != __uuidof(Rdp::IMsTscAxEvents))
            return E_NOINTERFACE;
        *target = static_cast<IDispatch*>(this);
        AddRef();
        return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return InterlockedIncrement(&refs); }
    ULONG STDMETHODCALLTYPE Release() override {
        const ULONG count = InterlockedDecrement(&refs);
        if (!count) delete this;
        return count;
    }
    HRESULT STDMETHODCALLTYPE GetTypeInfoCount(UINT* count) override {
        if (!count) return E_POINTER;
        *count = 0;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetTypeInfo(UINT, LCID, ITypeInfo**) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetIDsOfNames(REFIID, LPOLESTR*, UINT, LCID, DISPID*) override {
        return DISP_E_UNKNOWNNAME;
    }
    HRESULT STDMETHODCALLTYPE Invoke(DISPID, REFIID, LCID, WORD, DISPPARAMS*, VARIANT*,
                                     EXCEPINFO*, UINT*) override;
};

struct Session {
    HWND host = nullptr;
    HWND notify = nullptr;
    UINT message = 0;
    ComPtr<Rdp::IMsRdpClient10> client;
    ComPtr<IConnectionPoint> point;
    ComPtr<EventSink> sink;
    DWORD cookie = 0;
    std::array<Notice, 32> notices{};
    size_t first = 0, count = 0;
    int width = 1024, height = 768;
    bool attempted = false;

    ~Session() {
        if (sink) sink->session = nullptr;
        if (point && cookie) point->Unadvise(cookie);
        if (client && attempted) client->Disconnect();
        client.Reset();
        if (host && IsWindow(host)) DestroyWindow(host);
    }

    void push(const Notice& notice) {
        if (count == notices.size()) {
            first = (first + 1) % notices.size();
            --count;
        }
        notices[(first + count) % notices.size()] = notice;
        ++count;
        PostMessageW(notify, message, 0, 0);
    }
};

HRESULT STDMETHODCALLTYPE EventSink::Invoke(DISPID id, REFIID, LCID, WORD,
    DISPPARAMS* args, VARIANT*, EXCEPINFO*, UINT*) {
    if (!session) return S_OK;
    auto it = std::find(events.begin(), events.end(), id);
    if (it == events.end()) return S_OK;
    Notice notice;
    notice.kind = static_cast<LONG>(it - events.begin() + 1);
    if (notice.kind >= 4) {
        if (!args || args->cArgs != 1 || args->rgvarg[0].vt != VT_I4)
            return DISP_E_TYPEMISMATCH;
        notice.reason = args->rgvarg[0].lVal;
    }
    if (notice.kind == 5) {
        Rdp::ExtendedDisconnectReasonCode reason{};
        if (SUCCEEDED(session->client->get_ExtendedDisconnectReason(&reason)))
            notice.extended = static_cast<LONG>(reason);
        BSTR text = nullptr;
        if (SUCCEEDED(session->client->GetErrorDescription(notice.reason, notice.extended, &text))
            && text) wcsncpy_s(notice.detail, text, _TRUNCATE);
        SysFreeString(text);
    }
    session->push(notice);
    return S_OK;
}

// Resolve dispinterface event IDs from the installed mstscax type library.
// Different kinds of status must never be inferred from timing or window titles.
static HRESULT advise(Session& session) {
    ComPtr<ITypeInfo> client_type, event_type;
    ComPtr<ITypeLib> library;
    UINT index;
    HRESULT hr = session.client->GetTypeInfo(0, LOCALE_USER_DEFAULT, &client_type);
    if (FAILED(hr)) return hr;
    hr = client_type->GetContainingTypeLib(&library, &index);
    if (FAILED(hr)) return hr;
    hr = library->GetTypeInfoOfGuid(__uuidof(Rdp::IMsTscAxEvents), &event_type);
    if (FAILED(hr)) return hr;
    session.sink.Attach(new(std::nothrow) EventSink());
    if (!session.sink) return E_OUTOFMEMORY;
    const wchar_t* names[] = {L"OnConnecting", L"OnConnected", L"OnLoginComplete",
                               L"OnLogonError", L"OnDisconnected", L"OnFatalError"};
    for (size_t i = 0; i < session.sink->events.size(); ++i) {
        LPOLESTR name = const_cast<LPOLESTR>(names[i]);
        hr = event_type->GetIDsOfNames(&name, 1, &session.sink->events[i]);
        if (FAILED(hr)) return hr;
    }
    ComPtr<IConnectionPointContainer> container;
    hr = session.client.As(&container);
    if (FAILED(hr)) return hr;
    hr = container->FindConnectionPoint(__uuidof(Rdp::IMsTscAxEvents), &session.point);
    if (FAILED(hr)) return hr;
    session.sink->session = &session;
    return session.point->Advise(session.sink.Get(), &session.cookie);
}

extern "C" HRESULT rdp_create(HWND parent, HWND notify, UINT message, Session** out) {
    if (!out || !IsWindow(parent) || !IsWindow(notify)) return E_INVALIDARG;
    *out = nullptr;
    HMODULE atl = atl_module();
    if (!atl) return HRESULT_FROM_WIN32(ERROR_MOD_NOT_FOUND);
    using Init = BOOL(WINAPI*)();
    using Create = HRESULT(WINAPI*)(LPCOLESTR, HWND, IStream*, IUnknown**, IUnknown**,
                                    REFIID, IUnknown*);
    const auto init = reinterpret_cast<Init>(GetProcAddress(atl, "AtlAxWinInit"));
    const auto create = reinterpret_cast<Create>(GetProcAddress(atl, "AtlAxCreateControlEx"));
    if (!init || !create) return HRESULT_FROM_WIN32(ERROR_PROC_NOT_FOUND);
    if (!init()) return E_FAIL;
    auto s = std::unique_ptr<Session>(new(std::nothrow) Session());
    if (!s) return E_OUTOFMEMORY;
    s->notify = notify;
    s->message = message;
    s->host = CreateWindowExW(0, L"STATIC", L"", WS_CHILD|WS_VISIBLE|WS_TABSTOP|
        WS_CLIPCHILDREN|WS_CLIPSIBLINGS, 0, 0, 1, 1, parent, nullptr, GetModuleHandleW(nullptr), nullptr);
    if (!s->host) return HRESULT_FROM_WIN32(GetLastError());
    wchar_t clsid[40]{};
    StringFromGUID2(__uuidof(Rdp::MsRdpClient10NotSafeForScripting), clsid, 40);
    ComPtr<IUnknown> control;
    HRESULT hr = create(clsid, s->host, nullptr, nullptr, &control, IID_NULL, nullptr);
    if (FAILED(hr)) return hr;
    hr = control.As(&s->client);
    if (FAILED(hr)) return hr;
    hr = advise(*s);
    if (FAILED(hr)) return hr;
    *out = s.release();
    return S_OK;
}

// Stop immediately on a rejected security setting; Connect is always last.
#define CHECK(call) do { HRESULT result = (call); if (FAILED(result)) return result; } while (false)
extern "C" HRESULT rdp_connect(Session* s, const wchar_t* host, unsigned short port, BOOL clipboard) {
    if (!s || !host || !*host || !port || s->attempted) return E_INVALIDARG;
    s->attempted = true;
    ComPtr<Rdp::IMsRdpClientAdvancedSettings8> adv;
    ComPtr<Rdp::IMsRdpClientNonScriptable4> login;
    CHECK(s->client->get_AdvancedSettings9(&adv));
    CHECK(s->client.As(&login));
    // The type library uses wireHWND for an in-process HWND here. Parent the
    // OS credential / certificate dialogs to the visible technician window.
    CHECK(login->put_UIParentWindowHandle(reinterpret_cast<wireHWND>(s->notify)));
    CHECK(login->put_EnableCredSspSupport(VARIANT_TRUE));
    CHECK(login->put_PromptForCredentials(VARIANT_TRUE));
    CHECK(login->put_PromptForCredsOnClient(VARIANT_TRUE));
    CHECK(login->put_AllowCredentialSaving(VARIANT_FALSE));
    CHECK(adv->put_AuthenticationLevel(2));  // Windows validates and owns any identity warning
    CHECK(adv->put_EnableAutoReconnect(VARIANT_FALSE));
    CHECK(adv->put_RDPPort(port));
    CHECK(adv->put_overallConnectionTimeout(30));
    CHECK(adv->put_RedirectClipboard(clipboard ? VARIANT_TRUE : VARIANT_FALSE));
    CHECK(adv->put_RedirectDrives(VARIANT_FALSE));
    CHECK(adv->put_RedirectPrinters(VARIANT_FALSE));
    CHECK(adv->put_RedirectPorts(VARIANT_FALSE));
    CHECK(adv->put_RedirectSmartCards(VARIANT_FALSE));
    CHECK(adv->put_SmartSizing(VARIANT_TRUE));
    CHECK(s->client->put_DesktopWidth(std::clamp(s->width,  200, 8192)));
    CHECK(s->client->put_DesktopHeight(std::clamp(s->height, 200, 8192)));
    CHECK(s->client->put_ColorDepth(32));
    BSTR name = SysAllocString(host);
    if (!name) return E_OUTOFMEMORY;
    const HRESULT hr = s->client->put_Server(name);
    SysFreeString(name);
    if (FAILED(hr)) return hr;
    return s->client->Connect();
}

extern "C" void rdp_resize(Session* s, int x, int y, int width, int height) {
    s->width = width;
    s->height = height;
    SetWindowPos(s->host, nullptr, x, y, std::max(width, 0), std::max(height, 0),
                 SWP_NOZORDER | SWP_NOACTIVATE);
}
extern "C" HRESULT rdp_sync_display(Session* s) {
    if (s->width < 200 || s->height < 200) return S_FALSE; // hidden/minimized viewport
    // [MS-RDPEDISP] requires even pixel widths; physical dimensions are millimeters.
    const int width = std::min(s->width, 8192) & ~1;
    const int height = std::min(s->height, 8192);
    const UINT dpi = GetDpiForWindow(s->host);
    if (!dpi) return E_FAIL;
    const int scale = std::clamp(MulDiv(dpi, 100, 96), 100, 500);
    return s->client->UpdateSessionDisplaySettings(
        width, height, MulDiv(width, 254, dpi * 10), MulDiv(height, 254, dpi * 10),
        0, scale, 100);
}
extern "C" void rdp_focus(Session* s) {
    ComPtr<IOleInPlaceActiveObject> active;
    HWND child = nullptr;
    if (SUCCEEDED(s->client.As(&active)) && SUCCEEDED(active->GetWindow(&child)) && child)
        SetFocus(child);
    else
        SetFocus(s->host);
}
extern "C" HRESULT rdp_disconnect(Session* s) { return s->client->Disconnect(); }
extern "C" void rdp_destroy(Session* s) { delete s; }
extern "C" BOOL rdp_poll(Session* s, Notice* result) {
    if (!s->count) return FALSE;
    *result = s->notices[s->first];
    s->first = (s->first + 1) % s->notices.size();
    --s->count;
    return TRUE;
}
