/*
 * This is a demo script to show you how to connect successfully.
 * The code will be callback hell because it's easy and just to show you the basics.
 *
 * Make sure the account has access to Rocket League. (Family sharing untested)
 */

const RLAppId = 252950; // https://steamdb.info/app/252950/
const RLEndpoint = 'https://api.rlpp.psynet.gg/Services';
const RLKey = 'c338bd36fb8c42b1a431d30add939fc7';

const RLUserAgent = 'RL Win/211123.48895.355454 gzip';
const RLLanguage = 'INT';
const RLFeatureSet = 'PrimeUpdate36_2';
const RLBuildId = '-960700785';
const RLEnvironment = 'Prod';

const Config = require('./demo_config');
const Utils = require('./lib/utils');
const SteamUser = require('steam-user');
const CryptoJS = require('crypto-js');
const WebSocket = require('ws')



let request = require('request');
let clientSteam = new SteamUser();

// Step 0: Verify config.
if (!Config.username) {
    console.log('Field "username" is missing from the config.');
    return;
}

if (!Config.password) {
    console.log('Field "password" is missing from the config.');
    return;
}

if (!Config.displayName) {
    console.log('Field "displayName" is missing from the config.');
    return;
}


if (!Config.EpicAccountID) {
    console.log('Field "EpicAccountID" is missing from the config.');
    return;
}

// Step 1: Sign into Steam.
clientSteam.logOn({
    'accountName': Config.username,
    'password': Config.password
});

clientSteam.on('loggedOn', details => {
    console.log('[Steam] Signed into Steam as ' + clientSteam.steamID + '.');

    // Step 2: Request an appticket (AuthTicket).
    clientSteam.getEncryptedAppTicket(RLAppId, null, (err, ticket) => {
        if (err) {
			console.log("[Steam] AppTicket error: " + err);
            return;
        }

        console.log('[Steam] Received an appticket.');

        // Step 3: Authenticate at RocketLeague.
        let authRequest = JSON.stringify([
            {
                Service: 'Auth/AuthPlayer',
                Version: 2,
                ID: 1,
                Params: {
                    Platform: 'Steam',
                    PlayerName: Config.displayName,
                    PlayerID: clientSteam.steamID.getSteamID64(),
                    Language: RLLanguage,
                    AuthTicket: Utils.bufferToHex(ticket).toUpperCase(),
                    EpicAuthTicket: Utils.bufferToHex(ticket).toUpperCase(),
                    BuildRegion: '',
                    FeatureSet: RLFeatureSet,
                    bSkipAuth: false,
		    EpicAccountID: Config.EpicAccountID
                }
            }
        ]);
		
		

        let authSignature = CryptoJS.HmacSHA256('-' + authRequest, RLKey).toString();
		

        request.post({
            url: RLEndpoint,
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'User-Agent': RLUserAgent,
                'Cache-Control': 'no-cache',
                'PsyBuildID': RLBuildId,
                'PsyEnvironment': RLEnvironment,
                'PsyRequestID': 'PsyNetMessage_X_0',
                'PsySig': Buffer.from(authSignature, 'hex').toString('base64')
            },
            body: authRequest
        }, (error, response, body) => {
            if (error) {
                return console.log('[RocketLeague] Auth failed: ' + error);
            }
		
            // Step 4: Consume tokens to send authenticated requests.
            let authResponse = JSON.parse(body).Responses[0].Result;
            if (authResponse === undefined) {
                return console.log('[RocketLeague] Auth failed: ' + body);
            }

            let authWebsocket = authResponse.PerConURL;
            let authPsyToken = authResponse.PsyToken;
            let authSessionId = authResponse.SessionID;

            console.log('[RocketLeague] Auth was successful.');
            console.log('[RocketLeague] Connecting to RocketLeague through WebSocket.');
            
            const client = new WebSocket(authWebsocket, {
                headers: {
                    'PsyToken': authPsyToken,
                    'PsySessionID': authSessionId,
                    'PsyBuildID': RLBuildId,
                    'PsyEnvironment': RLEnvironment,
                    'User-Agent': RLUserAgent
                }
            });

            client.on('open', function () {
                console.log('[RocketLeague] Connected to WebSocket.')

                client.on('message', function (data) {
                    // Parse message.
                    let start = data.indexOf('\r\n\r\n')
                    if (start !== -1) {
                        start += 4
                        let dataLen = data.length - start;
                        if (dataLen === 0) {
                            // No message data.
                            console.log('No data was found.');
                        } else {
                            // We got a message.
                            let jsonString = data.substring(start);
                            let jsonPretty = JSON.stringify(JSON.parse(jsonString), null, 2);

                            console.log(jsonPretty);
                        }
                    }
                });

                console.log('[RocketLeague] Requesting inventory of signed in player..');

                // Create message.
                let msgBody = JSON.stringify([
                    {
                        Service: 'Products/GetPlayerProducts',
                        Version: 1,
                        ID: 3,
                        Params: {
                            PlayerID: 'Steam|' + clientSteam.steamID.getSteamID64() + '|0'
                        }
                    }
                ]);

                // Create signature for the message.
                let msgSignature = CryptoJS.HmacSHA256('-' + msgBody, RLKey).toString();
                let msgSignatureBase = Buffer.from(msgSignature, 'hex').toString('base64');

                // Setup headers.
                let msgHeaders = "PsySig: " + msgSignatureBase + "\r\n" +
                                 "PsyRequestID: PsyNetMessage_X_2\r\n" +
                                 "\r\n";

                // Create final message.
                let msgFinal = msgHeaders + msgBody;

                // Send message.
                client.send(msgFinal);
            })
        });
    });
});

clientSteam.on('error', function(e) {
    console.log(e);
});
