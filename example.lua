-- Przykład użycia
local secret_key = "tajny_klucz"
local payload = '{"sub":"1234567890","name":"John Doe","iat":' .. os.time() .. '}'
print("Payload: " .. payload)

-- Generowanie tokena
local token = exports["secure-token"]:generateToken(payload, secret_key)
print("Wygenerowany token: " .. token)

-- Walidacja tokena
local is_valid, data_or_err = exports["secure-token"]:validateToken(token, secret_key)
if is_valid then
  print("Token jest prawidłowy!")
  print("Payload tokena: " .. data_or_err)
else
  print("Błąd walidacji: " .. data_or_err)
end