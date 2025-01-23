fx_version 'cerulean'
game 'gta5'

description 'Generate and validate tokens like a JWT for FiveM resources'

server_scripts {
	'tokens.lua'
}

server_exports {
	'generateToken',
	'validateToken',
}