before collection implant meta data the connection should first be established. then bot will send the connection certificate fingerprint. once the server verifies the fingerprint it will request for the meta data to be collected. 

ordering of messages and encryption should be handled by the transport protocol

most capabilites/functionality should be implemented as modules that do not need to be defined in the protocol.

if some capabilites/functionality is defined within the protocol it is because it requires the server to process some messages in order to function or has its own window within the ui to help display its output.

header
+---------------+---------+------------+---------+---------+
| 2 bytes       | 2 bytes | 1 bytes    | 4 bytes | 4 bytes |
+---------------+---------+------------+---------+---------+
| message code  | flags   | session id | label   | length  |
+---------------+---------+------------+---------+---------+

message codes
+--------------+-------------------+
| message code | meaning           |
+--------------+-------------------+
| 0            | keep alive        | //built in
+--------------+-------------------+
| 1            | collect meta data | //built in
+--------------+-------------------+
| 2            | module            | //built in
| 2 | 0        | list              |
| 2 | 1        | load              |
| 2 | 2        | unload            |
| 2 | 3        | upload module     |
| 2 | 4        | command           |
+--------------+-------------------+
| 3            | file              | loaded
| 3 | 0        | copy              |
| 3 | 1        | move              |
| 3 | 2        | delete            |
| 3 | 3        | upload            |
| 3 | 4        | download          |
+--------------+-------------------+
| 4            | directory         | loaded
| 4 | 0        | print             |
| 4 | 1        | change            |
| 4 | 2        | create            |
| 4 | 3        | copy              |
| 4 | 4        | move              |
| 4 | 5        | list              |
| 4 | 6        | delete            |
+--------------+-------------------+
| 5 |          | drive             | loaded
| 5 | 5        | list              |
+--------------+-------------------+
| 6            | vnc               | loaded
| 6 | 1        | rgba data         |
| 6 | 2        | jpeg data         |
| 6 | 3        | mouse button      |
| 6 | 4        | mouse move        |
| 6 | 5        | send key          |
| 6 | 6        | get windows       |
| 6 | 7        | set window        |
| 6 | 8        | get desktops      |
| 6 | 9        | set desktop       |
| 6 | 10       | get clipboard     |
| 6 | 11       | set clipboard     |
| 6 | 12       | get browsers      | // includes profiles tide to browser
| 6 | 14       | launch browser    |
| 6 | 15       | resize window     |
| 6 | 16       | request fb update |
+--------------+-------------------+
| 7            | tunnel            | loaded
+--------------+-------------------+
| 6            | socks             | loaded
+--------------+-------------------+


------------------------------------------------------------------------------------------------------------

server will send a `LOAD_MODULE_REQUEST` to the bot, if the bot can find the module in its cache it will load the module using the requested method. If it can't it will send the server a `DOWNLOAD_MODULE_REQUEST` to download the required module.
LOAD_MODULE_REQUEST {
    Module_name: String,
    Load_method: String, disk|memory
    Module_hash: String,
}

modules will be treated differently based on their exports. if they export certain functions they will be added to the command handler switch statement.


exports:
builtin(
    [in,out] pointer to caller allocated memory
    [in] size of allocated memory
    [out] required amount of memory 
) 

builtin_function_struct {
    message_code:u32,
    function_address:u64,
}


the register export is implemented by a module to register functions that can be used by other functions that are not part of the builtin functions.

builtin functions will take in their request struct as an argument and return their response struct. 

modular functions should be exported as their command name. they should take in a string as their only argument.

the user will interact with the module on the command linke like so:
```
<module name> <function name> <input string>
```

modules should be able to have a dependenices export that indicates other modules that it depends on. the way this is handled is to be decided.


the bot will send a `LOAD_MODULE_RESPONSE` in response to a `LOAD_MODULE_REQUEST` or `TASK_ERROR` if the task eventually fails for any reason.
status: uint16 downloading (status = running) -> loaded
LOAD_MODULE_RESPONSE {
    Output: string

}


------------------------------------------------------------------------------------------------------------

server will track the modules that a bot has access to, when a request to load a module is made the server will first check that the bot has the specified module. if it does not if will first send a module upload request to the bot.

an simpler alternative to an upload_module_request is to have an option field in to load_module_request. the module will only be present in the load request if its not cached.

UPLOAD_MODULE_REQUEST {
    Module_name: String,
    Module_hash: String,
    Content     []byte,
}

------------------------------------------------------------------------------------------------------------

UNLOAD_MODULE_REQUEST {
    Module_name: String,
}

UNLOAD_MODULE_RESPONSE is `TASK_ERROR` if any error occurs otherwise the only response is the header indicating success.

------------------------------------------------------------------------------------------------------------

`LIST_MODULE_REQUEST` just consists of the message code in the header and contains no body

LIST_MODULE_RESPONSE {
    modules: [n]strings,
}

------------------------------------------------------------------------------------------------------------

module_command is used to interact with external modules, the format of the user given command should be `module-<exported function> <input>`. the command should be parsed on the server.

MODULE_COMMAND_REQUEST {
    module_name:String,
    function:String,
    input_options:String,
}

MODULE_COMMAND_RESPONSE {
    output:string
}

------------------------------------------------------------------------------------------------------------

### FILE-COPY-REQ

```text
FILE-COPY-REQ {
  source       [1]  String
  destination  [2]  String
  force        [3]  Boolean  OPTIONAL
}
```

### FILE-MOVE-REQ

```text
FILE-MOVE-REQ {
  source       [1]  String
  destination  [2]  String
}
```

### FILE-DELETE-REQ

```text
FILE-DELETE-REQ {
  path  [1]  String
}
```

### FILE-UPLOAD-REQ

```text
FILE-UPLOAD-REQ {
  destination  [1]  String
  content      [2]  SEQUENCE of Byte
}
```

### FILE-DOWNLOAD-REQ

```text
FILE-DOWNLOAD-REQ {
  path  [1]  String
}
```

### FILE-DOWNLOAD-REP

```text
FILE-DOWNLOAD-REP {
  current-chuck  [1]  UInt16
  total-chunks   [2]  UInt16
  chunk-content  [3]  SEQUENCE of Byte
}
```

### DIR-PRINT-REP

```text
DIR-PRINT-REP {
  path  [1]  String
}
```

### DIR-CHANGE-REQ

```text
DIR-CHANGE-REQ {
  path  [1]  String  OPTIONAL
}
```

If the `path` field is *not* set, the implant SHOULD change it's working directory to a 'default' location (e.g. the user's home directory).

### DIR-CREATE-REQ

```text
DIR-CREATE-REQ {
  path  [1]  String
}
```

### DIR-CREATE-REP

```text
DIR-CREATE-REP {
  entry  [1]  [FileSystemEntry]
}
```

### DIR-COPY-REQ

```text
DIR-COPY-REQ {
  source       [1]  String
  destination  [2]  String
}
```

### DIR-MOVE-REQ

```text
DIR-MOVE-REQ {
  source       [1]  String
  destination  [2]  String
}
```

### DIR-LIST-REQ

```text
DIR-LIST-REQ {
  path            [1]  String   OPTIONAL
  access-control  [2]  Boolean  OPTIONAL
}
```

If the `path` field is *not* set, the implant SHOULD list its current working directory.

### DIR-LIST-REP

```text
DIR-LIST-REP {
  entries  [1]  SEQUENCE of [FileSystemEntry]
}
```

### DIR-DELETE-REQ

```text
DIR-DELETE-REQ {
  path     [1]  String
  recurse  [2]  Boolean  OPTIONAL
}
```

### FileSystemEntry

```text
FileSystemEntry {
  path            [1]  String
  length          [2]  UInt32                      OPTIONAL
  attributes      [3]  [FileAttributes]            OPTIONAL
  owner           [4]  String                      OPTIONAL
  created         [5]  Timestamp                   OPTIONAL
  last-accessed   [6]  Timestamp                   OPTIONAL
  last-written    [7]  Timestamp                   OPTIONAL
  access-control  [8]  SEQUENCE of [FileSecurity]  OPTIONAL
}
```

### FileAttributes

Bitwise flags.

```text
FileAttributes {
  Normal     = 1,
  Archive    = 2,
  Compressed = 4,
  ReadOnly   = 8,
  Hidden     = 16,
  Directory  = 32,
  System     = 64
}
```

### FileSecurity

```text
FileSecurity {
  identity     [1]  String
  access-mask  [2]  Int32
  inheritance  [3]  [Inheritance]  OPTIONAL
  propagation  [4]  [Propagation]  OPTIONAL
}
```

### Inheritance

Bitwise flags.

```text
Inheritance {
  None             = 0,
  ContainerInherit = 1,
  ObjectInherit    = 2,
}
```

### Propagation

Bitwise flags.

```text
Propagation {
  None               = 0,
  NoPropagateInherit = 1,
  InheritOnly        = 2,
}
```

TASK_ERROR {
  error-code  [1]  UInt32
  message     [2]  String  OPTIONAL
}

## VNC messages

```
frame buffer request
+--------------+--------------+---------------+--------------+
| u16          | u32          | u32           | string       |
+--------------+--------------+---------------+--------------+
| is_key_frame | viewer width | viewer height | resouce name |
+--------------+--------------+---------------+--------------+

frame buffer response
rgba array
+----------+--------+----------+----------+------------+
| 2 bytes | 2 bytes | 2 bytes  | 2 bytes  | n bytes    |
+---------+---------+----------+----------+------------+
| width   | height  | x offset | y offset | rgba array |
+---------+---------+----------+----------+------------+

jpeg data
+----------+--------+----------+----------+------------+
| 2 bytes | 2 bytes | 2 bytes  | 2 bytes  | n bytes    |
+---------+---------+----------+----------+------------+
| width   | height  | x offset | y offset | jpeg array |
+---------+---------+----------+----------+------------+

resize window
+----------+----------+
| 2 bytes  | 2 bytes  |
+----------+----------+
| uint16   | uint16   |
| width    | height   |
+----------+----------+

request frame buffer update
+-----------------------+
| 1 byte                |
+-----------------------+
| 0 = keyframe false    |
| 1 = keyframe positive |
+-----------------------+
```

```
device control
0 = up
1 = down

mouse move
+----------+----------+
| 4 bytes  | 4 bytes  |
+----------+----------+
| x offset | y offset |
+----------+----------+

mouse button
+------------------+----------+-----------+----------+----------+
| 1 byte           | 4 bytes  | 1 bytes   | 4 bytes  | 4 bytes  |
+------------------+----------+-----------+----------+----------+
| virtual_key_code | scancode | direction | x offset | y offset |
+------------------+----------+-----------+----------+----------+

send key
+------------------+----------+-----------+
| 1 byte           | 4 bytes  | 1 bytes   |
+------------------+----------+-----------+
| virtual_key_code | scancode | direction |
+------------------+----------+-----------+
```