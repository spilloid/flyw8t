// Development probe only. Capture is limited to this window; tagged input targets this PID.
// No networking, desktop images, real keystroke logging, installed service or remote control.
import AppKit
import ApplicationServices
import ScreenCaptureKit
import CoreMedia
import CoreVideo

final class InputFixture: NSView {
    var observed: ((Bool) -> Void)?
    var token: Int64 = 0
    override var acceptsFirstResponder: Bool { true }
    override func draw(_ dirtyRect: NSRect) {
        NSColor.systemBlue.setFill()
        NSBezierPath(rect: bounds).fill()
        ("flyw8t: this process's capture/input fixture" as NSString).draw(
            at: NSPoint(x: 16, y: 24),
            withAttributes: [.font: NSFont.systemFont(ofSize: 20), .foregroundColor: NSColor.white])
    }
    override func keyDown(with event: NSEvent) { record(event, down: true) }
    override func keyUp(with event: NSEvent) { record(event, down: false) }
    private func record(_ event: NSEvent, down: Bool) {
        guard token != 0, event.keyCode == 0,
              event.cgEvent?.getIntegerValueField(.eventSourceUserData) == token else { return }
        observed?(down)
    }
}

@available(macOS 13.0, *)
final class MacProbe: NSObject, NSApplicationDelegate, SCStreamOutput, SCStreamDelegate {
    let reportURL: URL
    var window: NSWindow!
    let status = NSTextField(wrappingLabelWithString: "No permission prompts, capture or input until you choose a test.")
    let fixture = InputFixture()
    var capture: SCStream?
    var generation = 0
    var frames = 0
    var width = 0
    var height = 0
    var keyDowns = 0
    var keyUps = 0
    var events: [[String: Any]] = []

    init(reportURL: URL) { self.reportURL = reportURL }

    func applicationDidFinishLaunching(_ notification: Notification) {
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 680, height: 500),
                          styleMask: [.titled, .closable, .miniaturizable], backing: .buffered, defer: false)
        window.title = "flyw8t Mac feasibility probe (development only)"
        window.isReleasedWhenClosed = false
        let content = window.contentView!
        let buttons: [(String, Selector)] = [
            ("Refresh permission status", #selector(refresh)),
            ("Request screen capture permission", #selector(requestScreen)),
            ("Request Accessibility permission", #selector(requestAccessibility)),
            ("Capture this window for five seconds", #selector(startCapture)),
            ("Test input in this process", #selector(testInput)),
            ("Stop capture", #selector(stopCapture))]
        for (index, item) in buttons.enumerated() {
            let button = NSButton(title: item.0, target: self, action: item.1)
            button.frame = NSRect(x: 20 + (index % 2) * 330, y: 450 - (index / 2) * 40, width: 310, height: 32)
            content.addSubview(button)
        }
        status.frame = NSRect(x: 20, y: 260, width: 640, height: 80)
        content.addSubview(status)
        fixture.frame = NSRect(x: 20, y: 20, width: 640, height: 220)
        fixture.observed = { [weak self] down in
            guard let self else { return }
            if down { self.keyDowns += 1 } else { self.keyUps += 1 }
            self.record("tagged_input_observed")
        }
        content.addSubview(fixture)
        window.center()
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        refresh()
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
    func applicationWillTerminate(_ notification: Notification) { record("terminated") }

    @objc func refresh() {
        status.stringValue = "Screen capture: \(CGPreflightScreenCaptureAccess()). Accessibility: \(AXIsProcessTrusted()). Frames: \(frames). Tagged key down/up: \(keyDowns)/\(keyUps)."
        record("permission_status")
    }

    @objc func requestScreen() {
        _ = CGRequestScreenCaptureAccess()
        refresh()
    }

    @objc func requestAccessibility() {
        let options = [kAXTrustedCheckOptionPrompt.takeUnretainedValue() as String: true] as CFDictionary
        _ = AXIsProcessTrustedWithOptions(options)
        refresh()
    }

    @objc func startCapture() {
        guard capture == nil else { return }
        guard CGPreflightScreenCaptureAccess() else {
            status.stringValue = "Screen capture permission is absent. Request it explicitly, then refresh (or reopen the app if macOS requires it)."
            record("capture_refused_without_permission")
            return
        }
        generation += 1
        let attempt = generation
        frames = 0
        Task { @MainActor in
            do {
                let content = try await SCShareableContent.excludingDesktopWindows(false, onScreenWindowsOnly: true)
                guard attempt == generation else { return }
                guard let ownWindow = content.windows.first(where: {
                    $0.owningApplication?.processID == ProcessInfo.processInfo.processIdentifier &&
                    $0.windowID == CGWindowID(window.windowNumber)
                }) else { throw NSError(domain: "flyw8t.probe", code: 1,
                                        userInfo: [NSLocalizedDescriptionKey: "The probe's own visible window was not shareable."]) }
                let config = SCStreamConfiguration()
                config.width = 640
                config.height = 480
                config.minimumFrameInterval = CMTime(value: 1, timescale: 10)
                config.pixelFormat = kCVPixelFormatType_32BGRA
                config.showsCursor = false
                config.capturesAudio = false
                let stream = SCStream(filter: SCContentFilter(desktopIndependentWindow: ownWindow),
                                      configuration: config, delegate: self)
                try stream.addStreamOutput(self, type: .screen, sampleHandlerQueue: .main)
                capture = stream
                try await stream.startCapture()
                guard attempt == generation else { try? await stream.stopCapture(); return }
                status.stringValue = "Capturing only this test window. No images are saved. Stop is local."
                record("capture_started")
                DispatchQueue.main.asyncAfter(deadline: .now() + 5) { [weak self] in
                    guard let self, self.generation == attempt else { return }
                    self.stopCapture()
                }
            } catch {
                guard attempt == generation else { return }
                let failed = capture
                capture = nil
                try? await failed?.stopCapture()
                status.stringValue = "Capture did not complete: \(error.localizedDescription)"
                record("capture_error")
            }
        }
    }

    @objc func stopCapture() {
        generation += 1 // invalidate shareable-content lookup or startCapture still in flight
        let old = capture
        capture = nil
        record("capture_stop_requested")
        Task { @MainActor in
            do { try await old?.stopCapture() }
            catch { status.stringValue = "Capture stop returned an error: \(error.localizedDescription)"; record("capture_stop_error"); return }
            refresh()
        }
    }

    func stream(_ stream: SCStream, didOutputSampleBuffer sampleBuffer: CMSampleBuffer, of type: SCStreamOutputType) {
        guard capture === stream, type == .screen, sampleBuffer.isValid,
              let attachments = CMSampleBufferGetSampleAttachmentsArray(sampleBuffer, createIfNecessary: false) as? [[SCStreamFrameInfo: Any]],
              let rawStatus = attachments.first?[.status] as? Int,
              rawStatus == SCFrameStatus.complete.rawValue,
              let pixels = CMSampleBufferGetImageBuffer(sampleBuffer) else { return }
        frames += 1
        width = CVPixelBufferGetWidth(pixels)
        height = CVPixelBufferGetHeight(pixels)
        if frames == 1 { record("complete_frame_observed") }
    }

    func stream(_ stream: SCStream, didStopWithError error: Error) {
        DispatchQueue.main.async { [weak self] in
            guard let self, self.capture === stream else { return }
            self.capture = nil
            self.generation += 1
            self.status.stringValue = "Capture stopped: \(error.localizedDescription)"
            self.record("capture_stopped_with_error")
        }
    }

    @objc func testInput() {
        guard AXIsProcessTrusted() else { status.stringValue = "Accessibility is absent. No input was sent."; record("input_refused_without_permission"); return }
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        guard window.makeFirstResponder(fixture) else { record("input_refused_without_target"); return }
        fixture.token = Int64.random(in: 1...Int64(Int32.max))
        keyDowns = 0
        keyUps = 0
        let pid = ProcessInfo.processInfo.processIdentifier
        for down in [true, false] {
            guard let event = CGEvent(keyboardEventSource: nil, virtualKey: 0, keyDown: down) else { record("input_event_creation_failed"); return }
            event.flags = []
            event.setIntegerValueField(.eventSourceUserData, value: fixture.token)
            event.postToPid(pid) // never post into the system-wide input stream
        }
        status.stringValue = "Sent tagged key down/up only to this process; the report records what the fixture actually receives."
        record("tagged_input_sent")
    }

    private func record(_ event: String) {
        events.append(["event": event, "at": ISO8601DateFormatter().string(from: Date())])
        #if arch(arm64)
        let architecture = "arm64"
        #else
        let architecture = "x86_64"
        #endif
        let report: [String: Any] = [
            "schema": 1, "release_gate_passed": false,
            "os": ProcessInfo.processInfo.operatingSystemVersionString, "architecture": architecture,
            "ssh_environment_present": ProcessInfo.processInfo.environment["SSH_CONNECTION"] != nil,
            "screen_capture_permission": CGPreflightScreenCaptureAccess(), "accessibility_permission": AXIsProcessTrusted(),
            "capture_scope": "probe_window_only", "complete_frames": frames, "width": width, "height": height,
            "input_scope": "probe_process_only", "tagged_key_down": keyDowns, "tagged_key_up": keyUps,
            "untested": ["system_wide_input", "mouse_input", "login_screen", "unattended_service", "remote_transport"],
            "events": events]
        do { try JSONSerialization.data(withJSONObject: report, options: [.prettyPrinted, .sortedKeys]).write(to: reportURL, options: .atomic) }
        catch { status.stringValue = "Could not write the observation report: \(error.localizedDescription)" }
    }
}

guard CommandLine.arguments.count == 2 else { fputs("Usage: Flyw8tMacProbe /absolute/path/to/report.json\n", stderr); exit(64) }
if #available(macOS 13.0, *) {
    let app = NSApplication.shared
    let probe = MacProbe(reportURL: URL(fileURLWithPath: CommandLine.arguments[1]))
    app.setActivationPolicy(.regular)
    app.delegate = probe
    withExtendedLifetime(probe) { app.run() }
} else { fputs("This development probe needs macOS 13 or later.\n", stderr); exit(1) }
