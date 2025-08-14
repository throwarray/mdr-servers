# HTTP / WS SERVERS
- communicate between scenes and macros.
- communicate with web socket clients (devices).
- These servers aren't recommended for production use.


## Servers
Scripts to be loaded into the `java code` action.

    Macrodroid version >= v5.56

### HttpServer http_server.java -> bool ended
- Move static directory '/http' to `/sdcard/http`
- Set the PORT `[lv=HTTP_SERVER_PORT]`
- Track status `[lv=http_server_up]`
- `true` returned on ended

### WebsocketServer ws_server.java -> bool ended
- Set the PORT `[lv=WS_SERVER_PORT]`
- Track status `[lv=WS_server_up]`
- `true` returned on ended

#### Notes
- The status variables aren't reliable. 
- Server threads may get terminated by the OS.
- IPC wasn't implemented. 
- Server-side routes are handled inside the java actions.
- Portions of this project were generated with the assistance of Copilot.

    POC / WIP 🤷‍♂️

## The project is actively seeking contributors & maintainers. Pull requests and bug reports are welcomed and very much appreciated.

## LICENSE MIT