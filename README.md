# sbtel Short Burst Transport Encryption Layer
SBTEL is a symmetric transport encryption layer system for the ESP8266 and other microcontroler.
It is optimized for low latency and portability and is using UDP for more possible connections. Quality of service needs to be managed in the applcation layer. If you don't want to put QoS into the application layer, just use TCP instead of UDP. 
This is a early BETA version of sbtel. There are a lot of lingual mistakes in the documentation and some bugs in the code.
I'm working on in. It should be stable next week.

## Dependencies
 - nodeMCU firmware
 - net,crypto,cjson,node,file modules

## Example server
```lua
dofile("sbtel.lua") --load sbtel module
sbtel.LoadMap("map.json") -- load connection settings
sbtel.setID("A") -- set node id for outgoing traffic
srv = sbtel.bind(6666) -- bind UDP port 6666 for package reception
srv.reciever = function(sbtelSCK,id,data) --register callback for data reception
  print("recieved "..data.." from "..id)
  sbtelSCK:respond("bye")
  print("responded: bye")
end
```

### Example client
```lua
dofile("sbtel.lua") --load sbtel module
sbtel.LoadMap("map.json") -- load connection settings
sbtel.setID("B") -- set node id for outgoing traffic
sbtel.send("A","hi") -- sending package
```

## API

###sbtel.LoadMap(src)
Loads a json formatted connection map file

###sbtel.ls()
Shows all available sbtel connections (information will be printed but not returned)

###sbtel.setID(id)
Sets the sender ID for outgoing traffic

###sbtel.addCon(id,ip,key,iv)
Adds a new connection to the list of available connections (not saved to the json file)

###sbtel.remCon(id)
Removes a connection from the connection list

###sbtel.sendPackage(id,data)
Sends a package to the id node

###sbtel.bind(port)
Starts a sbtel sever listening on the given port

###sbtelServer:registerReciever(f)
Registers a function f as callback for message reception
prototype for such a function
```lua
function(sbtelSCK,id,data) end
```
