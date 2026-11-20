using System;
using System.Runtime.InteropServices;
using System.Text;
public static class TechnicianSmoke {
    private delegate bool Callback(IntPtr hwnd, IntPtr data);
    [DllImport("user32")] private static extern bool EnumWindows(Callback cb, IntPtr data);
    [DllImport("user32")] private static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint pid);
    [DllImport("user32", CharSet=CharSet.Unicode)] private static extern int GetClassName(IntPtr hwnd, StringBuilder text, int length);
    [DllImport("user32")] public static extern IntPtr GetDlgItem(IntPtr hwnd, int id);
    [DllImport("user32", CharSet=CharSet.Unicode, EntryPoint="SendMessageTimeoutW")]
    private static extern IntPtr ReadMessage(IntPtr hwnd, uint msg, UIntPtr count, StringBuilder text, uint flags, uint timeout, out UIntPtr result);
    [DllImport("user32")] public static extern bool PostMessage(IntPtr hwnd, uint msg, IntPtr w, IntPtr l);
    public static IntPtr Window(uint pid) {
        IntPtr found = IntPtr.Zero;
        EnumWindows((hwnd, data) => {
            uint owner;
            GetWindowThreadProcessId(hwnd, out owner);
            if (owner != pid) return true;
            var name = new StringBuilder(128);
            GetClassName(hwnd, name, name.Capacity);
            if (name.ToString() != "Flyw8tTechnicianWindow") return true;
            found = hwnd;
            return false;
        }, IntPtr.Zero);
        return found;
    }
    [DllImport("user32", EntryPoint="SendMessageTimeoutW")]
    private static extern IntPtr ReadSelection(IntPtr hwnd, uint msg, UIntPtr wparam, IntPtr lparam, uint flags, uint timeout, out UIntPtr result);

    public static int Selection(IntPtr root, int id) {
        var child = GetDlgItem(root, id);
        UIntPtr result;
        if (child == IntPtr.Zero || ReadSelection(child, 0x147, UIntPtr.Zero, IntPtr.Zero, 2, 500, out result) == IntPtr.Zero)
            return -1;
        return unchecked((int)result.ToUInt64()); // CB_GETCURSEL
    }

    public static string Label(IntPtr root, int id) {
        var child = GetDlgItem(root, id);
        if (child == IntPtr.Zero) return "";
        var text = new StringBuilder(1024);
        UIntPtr result;
        ReadMessage(child, 13, (UIntPtr)text.Capacity, text, 2, 500, out result);
        return text.ToString();
    }
}
