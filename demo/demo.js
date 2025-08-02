// Simple demo: Authenticate and connect to Rocket League's WebSocket API
// Uses Steam account credentials (family-shared works too)
// Epic Games accounts work, but the auth flow is more complex
import SteamUser from 'steam-user';
import WebSocket from 'ws';
import crypto from 'crypto';
import axios from 'axios';
import 'dotenv/config';

const PSY_KEY = 'c338bd36fb8c42b1a431d30add939fc7';
// Log: Using feature set FEATURE_SET
const FEATURE_SET = 'PrimeUpdate55_1';
// Log: BuildID: BUILD_ID from GPsyonixBuildID
const BUILD_ID = '-789534442';

const user = new SteamUser();

// Log into Steam using credentials from the environment
user.logOn({
    'accountName': process.env.NAME ?? (() => { throw new Error('NAME not set') })(),
    'password': process.env.PASS ?? (() => { throw new Error('PASS not set') })(),
});

user.on('loggedOn', async () => {
    // Generate a auth session ticket for Rocket League (App ID: 252950)
    const session = await user.createAuthSessionTicket(252950);
    const ticket = Buffer.from(session.sessionTicket).toString('hex').toUpperCase();

    // To my knowledge Rocket League only takes Epic access tokens now
    // The ticket is passed as an external auth token to get an Epic access token
    const epic = await axios.post(
        'https://api.epicgames.dev/epic/oauth/v2/token',
        new URLSearchParams({
            grant_type: 'external_auth',
            deployment_id: 'da32ae9c12ae40e8a112c52e1f17f3ba',
            external_auth_type: 'steam_session_ticket',
            external_auth_token: ticket,
        }), {
        auth: {
            username: 'xyza7891p5D7s9R6Gm6moTHWGloerp7B',
            password: 'Knh18du4NVlFs+3uQ+ZPpDCVto0WYf4yXP8+OcwVt1o',
        },
    }).then(res => res.data).catch(err => { throw new Error(err) });

    // The access token from the response is the new auth ticket
    const access_token = epic.access_token;
    const steam_id = user.steamID.getSteamID64();
    const epic_id = epic.account_id;

    // The route /rpc is used instead of /Services but that route still works
    const psynet = await axios.post(
        'https://api.rlpp.psynet.gg/rpc/Auth/AuthPlayer/v2',
        JSON.stringify({
            Platform: 'Steam',
            PlayerName: 'DEMO',
            PlayerID: steam_id,
            Language: 'INT',
            AuthTicket: access_token,
            BuildRegion: '',
            FeatureSet: FEATURE_SET,
            Device: 'PC',
            bSkipAuth: false,
            bSetAsPrimaryAccount: true,
            EpicAuthTicket: access_token,
            EpicAccountID: epic_id,
        }), {
        headers: {
            PsyBuildID: BUILD_ID,
        },
    }).then(res => res.data.Result).catch(err => { throw new Error(err) });

    // To my knowledge the v1 url does not work anymore so v2 is used
    const wss = new WebSocket(psynet.PerConURLv2, {
        headers: {
            PsyToken: psynet.PsyToken,
            PsySessionID: psynet.SessionID,
            PsyBuildID: BUILD_ID,
            PsyEnviornment: 'Prod',
        }
    });

    wss.on('open', async () => {
        // Services now use a new format `${Request} v${Version}`
        const service = 'Skills/GetPlayerSkill v1';
        const params = JSON.stringify({
            PlayerID: `Epic|${epic_id}|0`,
        });

        // Sign the request with the key
        const sig = crypto.createHmac('sha256', PSY_KEY).update(`-${params}`).digest('base64');

        // Build the headers for the message
        const headers = [
            `PsyService: ${service}`,
            'PsyRequestID: PsyNetMessage_X_1',
            `PsySig: ${sig}`,
        ].join("\r\n");

        wss.send(`${headers}\r\n\r\n${params}`);
    });

    // Parse incoming WebSocket messages
    wss.on('message', msg => {
        const [headers, body] = msg.toString().split('\r\n\r\n');
        console.log(`${headers}\n${body}`);
    });

    wss.on('error', err => {
        throw new Error(err);
    });
});

user.on('error', (err) => {
    throw new Error(err);
});