# Fivem Secure token

If u want secure your client side in the FiveM scripts, u can use this simple lib `secure-token`.

### Why the hell would i want to use this

It's simple. To keep your script safe from **bad guys**.

### Example flow with nui (e.g police mdt or something):

1. Sign in to mdt on login page with login and password
2. Script will send data like this: `nui -> client -> server -> client -> nui`
3. In that server part u can after verifying user, generate random secret and use `command` to generate token, save secret in sessions table in db and return success with token.
4. Save token on client or nui
5. Use that saved token in every call requests to server

```lua
-- example of use
local secret_key = "random_and_very_secret_key"
local payload = '{"sub":"1234567890","name":"John Doe","iat":' .. os.time() .. '}'
print("Payload: " .. payload)

-- generate token
local token = exports["secure-token"]:generateToken(payload, secret_key)
print("generated token: " .. token)

local is_valid, just_data = exports["secure-token"]:verifyToken(token)
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
```
