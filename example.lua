-- example of use
local secret_key = "random_and_very_secret_key"
local payload = '{"sub":"1234567890","name":"John Doe","iat":' .. os.time() .. '}'
print("Payload: " .. payload)

-- generate token
local token = exports["secure-token"]:generateToken(payload, secret_key)
print("generated token: " .. token)

local is_valid, just_data = exports["secure-token"]:getPayload(token)
if is_valid then
  print("Payload: " .. just_data)
else
  print("error: " .. just_data)
end

-- validate token
local is_valid, data_or_err = exports["secure-token"]:validateToken(token, secret_key)
if is_valid then
  print("Token is valid!")
  print("Token payload: " .. data_or_err)
else
  print("error: " .. data_or_err)
end