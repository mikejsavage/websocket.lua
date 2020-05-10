A pure Lua, bring your own socket websocket server library.

It only provides low level handshake and frame functions, so you can use
it with whatever socket library you like, and you can use it to support
websockets and raw connections on a single port.

Depends only on LPeg and Lua 5.3


# Usage

```lua
require( "websocket" )

local socket = <bring your own socket>

local data = ""

local completed_handshake = false

local frames = { }
local expect_continuation_frame = false

while true do
	data = data .. socket:receive()

	if not completed_handshake then
		local ok, len, response = websocket.handshake( data )
		if ok then
			completed_handshake = true
			data = data:sub( len )
			socket:send( response )
			socket:send( websocket.text( "hello" ) )
		end
	end

	if completed_handshake then
		while true do
			local frame, len = websocket.parse_frame( data )
			if not frame then
				break
			end

			local ok, data, response
			ok, data, response, expect_continuation_frame = websocket.process_frame( frame, expect_continuation_frame )

			if data then
				table.insert( self.websocket.frames, data )

				if not expect_continuation_frame then
					-- do something with table.concat( frames, "" ), e.g.
					socket:send( websocket.binary( table.concat( frames, "" ) ) )
					frames = { }
				end
			end

			if response then
				socket:send( response )
			end

			if not ok then
				socket:shutdown()
			end
		end
	end
end
```
