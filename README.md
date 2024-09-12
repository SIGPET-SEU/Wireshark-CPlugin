# Wireshark-CPlugin
This repository contains the Wireshark dissectors written in C, mainly for proxy protocols.

Since the wslua APIs only provide restricted capabilities, functions like `reassemble_streaming_data_and_call_subdissector` seem unavailable in Lua plugins. Therefore, I'm currently working on developing C dissectors. The Lua repository remains legacy for simple tests and quick validation. If wslua later provides more mechanisms, switching back to Lua is appealing :).
