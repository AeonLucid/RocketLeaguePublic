/*
 * This is a demo script to show you how to connect successfully.
 * The code will be callback hell because it's easy and just to show you the basics.
 *
 * Make sure the account has access to Rocket League. (Family sharing untested)
 */

const RLAppId = 252950; // https://steamdb.info/app/252950/
const RLEndpoint = 'https://psyonix-rl.appspot.com/Services';
const RLKey = 'c338bd36fb8c42b1a431d30add939fc7';

const RLUserAgent = 'RL Win/181015.37783.212225 gzip';
const RLLanguage = 'INT';
const RLGameVersion = 25;
const RLFeatureSet = 'FeatureUpdate22_1';
const RLBuildId = '-112028592';

const Config = require('./demo_config');
const Utils = require('./lib/utils');
const SteamUser = require('steam-user');
const CryptoJS = require('crypto-js');

let request = require('request');
let clientSteam = new SteamUser();

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
                Version: 1,
                ID: 2,
                Params: {
                    Platform: 'Steam',
                    PlayerName: Config.displayName,
                    PlayerID: clientSteam.steamID.getSteamID64(),
                    GameVersion: RLGameVersion,
                    Language: RLLanguage,
                    AuthTicket: Utils.bufferToHex(ticket).toUpperCase(),
                    BuildRegion: '',
                    FeatureSet: RLFeatureSet,
                    bTrial: false,
                    bSkipAuth: false
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
                'PsyEnvironment': 'Prod',
                'PsyRequestID': 'PsyNetMessage_X_3',
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

            let authSessionId = authResponse.SessionID;
            let authPsyToken = authResponse.PsyToken;

            console.log('[RocketLeague] Auth was successful.');
            console.log('[RocketLeague] Fetching inventory of signed in player..');

            // It's now possible to make authenticated requests.
            // Step 5: Make an authenticated request.
            let productsRequest = JSON.stringify([
                {
                    Service: 'Products/GetPlayerProducts',
                    Version: 1,
                    ID: 3,
                    Params: {
                        PlayerID: 'Steam|' + clientSteam.steamID.getSteamID64() + '|0'
                    }
                }
            ]);

            let productsSignature = CryptoJS.HmacSHA256('-' + productsRequest, RLKey).toString();

            request.post({
                url: RLEndpoint,
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'User-Agent': RLUserAgent,
                    'Cache-Control': 'no-cache',
                    'PsyBuildID': RLBuildId,
                    'PsyEnvironment': 'Prod',
                    'PsyRequestID': 'PsyNetMessage_X_4',
                    'PsySig': Buffer.from(productsSignature, 'hex').toString('base64'),
                    'PsyToken': authPsyToken,
                    'PsySessionID': authSessionId
                },
                body: productsRequest
            }, (error, response, body) => {
                if (error) {
                    return console.log('[RocketLeague] Auth failed: ' + error);
                }

                let productsResponse = JSON.parse(body).Responses[0].Result.ProductData;

                for (let i = 0; i < productsResponse.length; i++) {
                    let product = productsResponse[i];

                    console.log('[RocketLeague] ProductID ' + product.ProductID + ' InstanceID ' + product.InstanceID);
                }
            });
        });
    });
});

clientSteam.on('error', function(e) {
    console.log(e);
});