local lpeg = require( "lpeg" )

local http_request_parser
do
	local key = ( 1 - lpeg.S( ":\r\n" ) ) ^ 1
	local value = ( 1 - lpeg.S( "\r\n" ) ) ^ 1
	local whitespace = lpeg.S( " \t" ) ^ 0
	local header = ( lpeg.C( key ) / string.lower ) * lpeg.P( ":" ) * whitespace * lpeg.C( value ) * whitespace * lpeg.P( "\r\n" )
	http_request_parser = lpeg.P( "GET / HTTP/1.1\r\n" ) * lpeg.Ct( lpeg.Ct( header ) ^ 0 ) * lpeg.P( "\r\n" ) * lpeg.Cp()
end

local base64_chars = {
	"A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M",
	"N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z",
	"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m",
	"n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z",
	"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "+", "/",
}

local function base64( data )
	local result = { }

	for i = 1, #data, 3 do
		local a = data:byte( i ) or 0
		local b = data:byte( i + 1 ) or 0
		local c = data:byte( i + 2 ) or 0

		local triple = bit32.bor( bit32.lshift( a, 16 ), bit32.lshift( b, 8 ), c )

		table.insert( result, base64_chars[ 1 + bit32.band( bit32.rshift( triple, 18 ), 0x3f ) ] )
		table.insert( result, base64_chars[ 1 + bit32.band( bit32.rshift( triple, 12 ), 0x3f ) ] )
		table.insert( result, base64_chars[ 1 + bit32.band( bit32.rshift( triple, 6 ), 0x3f ) ] )
		table.insert( result, base64_chars[ 1 + bit32.band( triple, 0x3f ) ] )
	end

	local trim = ( 3 - #data % 3 ) % 3

	return table.concat( result, "" ):sub( 1, -trim - 1 ) .. string.rep( "=", trim )
end

local unpack_be32x16 = ">" .. string.rep( "I4", 16 )

local function sha1( msg )
	local h0 = 0x67452301
	local h1 = 0xEFCDAB89
	local h2 = 0x98BADCFE
	local h3 = 0x10325476
	local h4 = 0xC3D2E1F0

	local bit_len = #msg * 8

	-- append "1" bit
	msg = msg .. string.char( 0x80 )

	-- pad to multiple of 64 minus 64bits
	local padding_len = ( 64 - ( #msg + 8 ) % 64 ) % 64
	msg = msg .. string.rep( string.char( 0 ), padding_len )

	-- append 64bit length
	msg = msg .. string.pack( ">I8", bit_len )
	assert( #msg % 64 == 0 )

	for i = 1, #msg, 64 do
		local words = { string.unpack( unpack_be32x16, msg, i ) }

		for j = 17, 80 do
			local xor = bit32.bxor( words[ j - 3 ], words[ j - 8 ], words[ j - 14 ], words[ j - 16 ] )
			words[ j ] = bit32.lrotate( xor, 1 )
		end

		local a = h0
		local b = h1
		local c = h2
		local d = h3
		local e = h4

		local function round( j, f, k )
			local temp = bit32.lrotate( a, 5 ) + f + e + k + words[ j ]
			e = d
			d = c
			c = bit32.lrotate( b, 30 )
			b = a
			a = temp
		end

		for j = 1, 20 do
			local f = bit32.bor( bit32.band( b, c ), bit32.band( bit32.bnot( b ), d ) )
			local k = 0x5A827999
			round( j, f, k )
		end

		for j = 21, 40 do
			local f = bit32.bxor( b, c, d )
			local k = 0x6ED9EBA1
			round( j, f, k )
		end

		for j = 41, 60 do
			local f = bit32.bor( bit32.band( b, c ), bit32.band( b, d ), bit32.band( c, d ) )
			local k = 0x8F1BBCDC
			round( j, f, k )
		end

		for j = 61, 80 do
			local f = bit32.bxor( b, c, d )
			local k = 0xCA62C1D6
			round( j, f, k )
		end

		h0 = h0 + a
		h1 = h1 + b
		h2 = h2 + c
		h3 = h3 + d
		h4 = h4 + e
	end

	-- truncate to 32bits
	h0 = bit32.band( h0, 0xFFFFFFFF )
	h1 = bit32.band( h1, 0xFFFFFFFF )
	h2 = bit32.band( h2, 0xFFFFFFFF )
	h3 = bit32.band( h3, 0xFFFFFFFF )
	h4 = bit32.band( h4, 0xFFFFFFFF )

	return string.pack( ">I4I4I4I4I4", h0, h1, h2, h3, h4 )
end

local _M = { }

function _M.handshake( data )
	local headers, len = http_request_parser:match( data )
	if not headers then
		return false
	end

	local version
	local key

	for _, header in ipairs( headers ) do
		if header[ 1 ] == "sec-websocket-version" then
			version = header[ 2 ]
		elseif header[ 1 ] == "sec-websocket-key" then
			key = header[ 2 ]
		end
	end

	if not key or version ~= "13" then
		return false
	end

	local accept = base64( sha1( key .. "258EAFA5-E914-47DA-95CA-C5AB0DC85B11" ) )
	local response = ""
		.. "HTTP/1.1 101 Switching Protocols\r\n"
		.. "Upgrade: websocket\r\n"
		.. "Connection: Upgrade\r\n"
		.. "Sec-WebSocket-Accept: " .. accept .. "\r\n"
		.. "\r\n"

	return true, len, response
end

local function make_frame( opcode, data, fin )
	local result = string.char( bit32.bor( fin and 0x80 or 0, opcode ) )

	if #data <= 125 then
		result = result .. string.char( #data )
	elseif #data <= 0xFFFF then
		result = result .. string.pack( ">BI2", 126, #data )
	else
		result = result .. string.pack( ">BI8", 127, #data )
	end

	return result .. data
end

local function close( code, message )
	local data = string.pack( "<I2", code ) .. message
	return make_frame( 0x8, data, true )
end

function _M.parse_frame( data )
	local ok, frame, len = pcall( function()
		local frame = { }
		local pos = 1

		local b0, b1
		b0, b1, pos = string.unpack( "BB", data, pos )

		frame.FIN = bit32.band( b0, 0x80 )
		frame.RSV1 = bit32.band( b0, 0x40 )
		frame.RSV2 = bit32.band( b0, 0x20 )
		frame.RSV3 = bit32.band( b0, 0x10 )
		frame.opcode = bit32.band( b0, 0x0F )
		local MASK = bit32.band( b1, 0x80 )

		local data_length = bit32.band( b1, 0x7F )

		if data_length == 126 then
			data_length, pos = string.unpack( ">I2", data, pos )
		elseif data_length == 127 then
			data_length, pos = string.unpack( ">I8", data, pos )
		end

		if MASK == 0 then
			frame.data = data:sub( pos, pos + data_length )
			pos = pos + data_length
			assert( #frame.data == data_length )
		else
			local key = { string.unpack( "BBBB", data, pos ) }
			table.remove( key, 5 )
			pos = pos + 4

			local unmasked = { }
			for i = 1, data_length do
				local byte
				byte, pos = string.unpack( "B", data, pos )
				table.insert( unmasked, string.char( bit32.bxor( byte, key[ ( ( i - 1 ) % 4 ) + 1 ] ) ) )
			end

			frame.data = table.concat( unmasked )
		end

		return frame, pos
	end )

	if not ok then
		return
	end

	return frame, len
end

-- returns keep open, data, response frame, expect_continuation
function _M.process_frame( frame, expect_continuation )
	if frame.RSV1 ~= 0 or frame.RSV2 ~= 0 or frame.RSV3 ~= 0 then
		return false, nil, close( 1002, "Reserved bits not zero" )
	end

	if ( frame.opcode >= 0x3 and frame.opcode <= 0x7 ) or frame.opcode >= 0xB then
		return false, nil, close( 1002, "Reserved opcode" )
	end

	if frame.opcode >= 0x8 then
		if #frame.data > 125 then
			return false, nil, close( 1002, "Data too long" )
		end

		if frame.FIN == 0 then
			return false, nil, close( 1002, "Fragmented control frame" )
		end
	end

	-- close frame
	if frame.opcode == 0x8 then
		return false
	end

	-- continuation frame
	if frame.opcode == 0x0 then
		if not expect_continuation then
			return false, nil, close( 1002, "Unexpected continuation frame" )
		end

		return true, frame.data, nil, frame.FIN == 0
	end

	-- text/binary frame
	if frame.opcode == 0x1 or frame.opcode == 0x2 then
		if expect_continuation then
			return false, nil, close( 1002, "Expected continuation frame" )
		end

		return true, frame.data, nil, frame.FIN == 0
	end

	-- ping
	if frame.opcode == 0x9 then
		return true, nil, make_frame( 0xa, frame.data, true ), expect_continuation
	end

	-- pong
	assert( frame.opcode == 0xa )
	return true, nil, nil, expect_continuation
end

function _M.text( data )
	return make_frame( 0x1, data, true )
end

function _M.binary( data )
	return make_frame( 0x2, data, true )
end

return _M
