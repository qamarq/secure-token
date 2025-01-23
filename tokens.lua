local function base64_encode(data)
  local b = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
  return ((data:gsub('.', function(x)
      local r, b = '', x:byte()
      for i = 8, 1, -1 do r = r .. (b % 2^i - b % 2^(i-1) > 0 and '1' or '0') end
      return r
  end) .. '0000'):gsub('%d%d%d?%d?%d?%d?', function(x)
      if (#x < 6) then return '' end
      local c = 0
      for i = 1, 6 do c = c + (x:sub(i, i) == '1' and 2^(6-i) or 0) end
      return b:sub(c + 1, c + 1)
  end) .. ({ '', '==', '=' })[#data % 3 + 1])
end

local function base64_decode(data)
  local b = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
  data = data:gsub('[^' .. b .. '=]', '')
  return (data:gsub('.', function(x)
      if (x == '=') then return '' end
      local r, f = '', (b:find(x) - 1)
      for i = 6, 1, -1 do r = r .. (f % 2^i - f % 2^(i-1) > 0 and '1' or '0') end
      return r
  end):gsub('%d%d%d%d%d%d%d%d', function(x)
      if (#x ~= 8) then return '' end
      local c = 0
      for i = 1, 8 do c = c + (x:sub(i, i) == '1' and 2^(8-i) or 0) end
      return string.char(c)
  end))
end

local function xor_encrypt(data, key)
  local encrypted = {}
  for i = 1, #data do
      local key_byte = key:byte((i - 1) % #key + 1)
      encrypted[i] = string.char((data:byte(i) ~ key_byte) % 256)
  end
  return table.concat(encrypted)
end

--- Generate token from payload and secret key
---@param payload string
---@param secret string
function generateToken(payload, secret)
  local header = '{"alg":"XOR256","type":"JWT"}'

  local encoded_header = base64_encode(header)
  local encoded_payload = base64_encode(payload)

  local signature = xor_encrypt(encoded_header .. "." .. encoded_payload, secret)

  local encoded_signature = base64_encode(signature)

  return encoded_header .. "." .. encoded_payload .. "." .. encoded_signature
end

--- Validate token with given secret key
---@param token string
---@param secret string
function validateToken(token, secret)
  local parts = {}
  for part in string.gmatch(token, "[^%.]+") do
      table.insert(parts, part)
  end

  if #parts ~= 3 then
      return false, "Nieprawidłowy format tokena"
  end

  local encoded_header, encoded_payload, encoded_signature = parts[1], parts[2], parts[3]

  local signature = base64_decode(encoded_signature)

  local expected_signature = xor_encrypt(encoded_header .. "." .. encoded_payload, secret)
  if signature ~= expected_signature then
      return false, "Nieprawidłowy podpis"
  end

  local payload = base64_decode(encoded_payload)
  return true, payload
end

--- Reading just payload from token
---@param token string
function getPayload(token)
  local parts = {}
  for part in string.gmatch(token, "[^%.]+") do
      table.insert(parts, part)
  end

  if #parts ~= 3 then
      return false, "Nieprawidłowy format tokena"
  end

  local encoded_payload = parts[2]

  local payload = base64_decode(encoded_payload)
  return true, payload
end
