set -xe

mkdir -p x64
mkdir -p x86
x86_64-w64-mingw32-gcc -Wformat -fPIC -static -shared -Iminhook_prebuilt/include main.c -Lminhook_prebuilt/bin/ -Wl,-Bdynamic -lMinHook.x64 -lntdll -lkernel32 -o x64/wintab32.dll
i686-w64-mingw32-gcc -Wl,--kill-at -Wl,--enable-stdcall-fixup -Wformat -fPIC -static -shared -Iminhook_prebuilt/include main.c -Lminhook_prebuilt/bin/ -Wl,-Bdynamic -lMinHook.x86 -lntdll -lkernel32 -o x86/wintab32.dll

cp minhook_prebuilt/bin/MinHook.x64.dll ./x64
cp minhook_prebuilt/bin/MinHook.x86.dll ./x86
