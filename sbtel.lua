-- Copyright 2016 Simon Diepold <simon.diepold@infinitycoding.de>
-- License: MIT

--SBTEL
--Short Burst Transport and Encryption Layer
-- key table entries {"id"={key="xxx", iv="xxx", cnt="x"},.....}
sbtel = {}

-- loads connection Map in JSON format
function sbtel.LoadMap(src)
    file.open(src,"r")
    local tmp = ""
    while true do
        local line = file.readline()
        if(line == nil) then
            break
        end
        tmp = tmp..line
    end
    ok, map = pcall(cjson.decode, tmp)
    if not ok then
        error("Json File could not be decoded")
    end
    sbtel.map = map
    sbtel.mapfile = src
end



-- shows current connections
function sbtel.ls()
    if(sbtel.map == nil) then
        print("no routes found")
    end
    print("ID,IP,Port,KEY,CNT")
    for k,v in pairs(sbtel.map) do
        print(k..":"..v.ip..":"..v.key..":"..v.cnt)
    end
end

-- sets current device ID
function sbtel.setID(id)
    sbtel.id = id
end

-- adds a new connection to the connection map
function sbtel.addCon(id,ip,key,iv)
        if(sbtel.map == nil) then
            sbtel.map = {}
        end
        sbtel.map[id] = {}
        sbtel.map[id].ip = ip
        sbtel.map[id].key = key
        sbtel.map[id].iv = iv
end

-- removes a connection from the connection map
function sbtel.remCon(id)
        if(sbtel.map == nil) then
            error("no connection found")
        end
        sbtel.map[id] = nil
        if(#sbtel.map[id] == 0) then
            sbtel.map = nil
        end
end


function sbtel.sendPackage(id,data)
            node.setcpufreq(node.CPU160MHZ)
              sbtel.map[id].cnt = sbtel.map[id].cnt+1
              local encPayload = crypto.encrypt("AES-CBC",sbtel.map[id].key,string.format("%x,%s",sbtel.map[id].cnt,data),sbtel.map[id].iv)
              encPayload = string.format("%s,%04x%04x%s",sbtel.id,#encPayload,32,encPayload)
              local signature = crypto.hmac("SHA256",encPayload, sbtel.map[id].key)
              local con = net.createConnection(net.UDP, 0)
              con:connect(sbtel.map[id].port,sbtel.map[id].ip)
              con:send(encPayload..signature)
            node.setcpufreq(node.CPU80MHZ)
            con:close()
            con = nil
end


sbtelSCK = {}
sbtelSCK.__index = sbtelSCK

function sbtelSCK:respond(data)
  node.setcpufreq(node.CPU160MHZ)
    sbtel.map[self.id].cnt = sbtel.map[self.id].cnt+1
    local encPayload = crypto.encrypt("AES-CBC",sbtel.map[self.id].key,string.format("%x,%s",sbtel.map[self.id].cnt,data),sbtel.map[self.id].iv)
    encPayload = string.format("%s,%04x%04x%s",sbtel.id,#encPayload,32,encPayload)
    local signature = crypto.hmac("SHA256",encPayload, sbtel.map[self.id].key)
    self.conn:send(encPayload..signature)
    print("data sended")
  node.setcpufreq(node.CPU80MHZ)
end


sbtelServer = {}
sbtelServer.__index = sbtelServer

-- creates a SBTEL UDP server
function sbtel.bind(port)
    local object = {}
    setmetatable(object,sbtelServer)
    srv=net.createServer(net.UDP)
    object.binding = srv
    srv:on("receive",function(conn, payload) object:handlePackage(conn,payload) end)
    srv:listen(port)
    return object
end

--f(id,content)
function sbtelServer:registerReciever(f)
    self.reciever = f
end



function sbtelServer:handlePackage(conn,payload)
    local id,dataSize,sigSize,rest = string.match(payload,"(.+),(%x%x%x%x)(%x%x%x%x)(.+)")
    if(id == nil or rest == nil or dataSize == nil or sigSize == nil) then
      print("invalid header")
      return
    end

    if(sbtel.map[id] == nil) then
      print("unknown sender")
      return
    end

    dataSize = tonumber(dataSize,16)
    sigSize = tonumber(sigSize,16)
    if(dataSize == nil or sigSize == nil) then
      print("invalid field sizes")
      return
    end

    local signature = rest:sub(dataSize+1)
    local verify = crypto.hmac("SHA256",payload:sub(1,#payload-sigSize),sbtel.map[id].key)
    if(signature ~= verify) then
      print("invalid signature")
      return
    end

    local rawdata = crypto.decrypt("AES-CBC",sbtel.map[id].key,rest:sub(1,dataSize),sbtel.map[id].iv)
    local serial,data = string.match(rawdata,"(%x),(.+)")

    if(serial == nil or data == nil) then
      print("invalid encrypted data")
      return
    end

    serial = tonumber(serial,16)
    if(serial <= sbtel.map[id].cnt) then
      print("replay")
      return
    end

    print(data)
    sbtel.map[id].cnt = serial
    if(self.reciever ~= nil) then
        print("callback!")
        local sck = {}
        setmetatable(sck,sbtelSCK)
        sck.conn = conn
        sck.id = id
        self.reciever(sck,data)
        sck.conn = nil
        sck = nil
    end
    conn:close()
    conn = nil
end
