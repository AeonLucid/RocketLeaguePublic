# 1. RocketLeaguePublic

This repository contains all information necessary to consume the `/Services` API of the game [Rocket League](https://store.steampowered.com/app/252950/Rocket_League/), which is also used by the game itself.

## 1.1. Terms of content

<!-- TOC -->

- [1. RocketLeaguePublic](#1-rocketleaguepublic)
    - [1.1. Terms of content](#11-terms-of-content)
    - [1.2. Endpoints](#12-endpoints)
    - [1.3. Intercepting requests](#13-intercepting-requests)
    - [1.4. Headers](#14-headers)
    - [1.5. Signing](#15-signing)
        - [1.5.1. Requests](#151-requests)
        - [1.5.2. Responses](#152-responses)
    - [1.6. Authentication](#16-authentication)
    - [1.7. Requests](#17-requests)
        - [1.7.1. Auth/AuthPlayer](#171-authauthplayer)
        - [1.7.2. Clubs/GetClubInvites](#172-clubsgetclubinvites)
        - [1.7.3. Clubs/GetPlayerClubDetails](#173-clubsgetplayerclubdetails)
        - [1.7.4. DLC/GetDLC](#174-dlcgetdlc)
        - [1.7.5. Filters/FilterContent](#175-filtersfiltercontent)
        - [1.7.6. GameServer/FindPrivateServer](#176-gameserverfindprivateserver)
        - [1.7.7. GameServer/GetGameServerPingList](#177-gameservergetgameserverpinglist)
        - [1.7.8. GenericStorage/GetPlayerGenericStorage](#178-genericstoragegetplayergenericstorage)
        - [1.7.9. GenericStorage/SetPlayerGenericStorage](#179-genericstoragesetplayergenericstorage)
        - [1.7.10. Matchmaking/PlayerCancelPrivateMatch](#1710-matchmakingplayercancelprivatematch)
        - [1.7.11. Matchmaking/PlayerSearchPrivateMatch](#1711-matchmakingplayersearchprivatematch)
        - [1.7.12. Metrics/RecordMetrics](#1712-metricsrecordmetrics)
        - [1.7.13. Microtransaction/ClaimEntitlements](#1713-microtransactionclaimentitlements)
        - [1.7.14. Players/GetChatBanStatus](#1714-playersgetchatbanstatus)
        - [1.7.15. Players/GetXP](#1715-playersgetxp)
        - [1.7.16. Population/UpdatePlayerPlaylist](#1716-populationupdateplayerplaylist)
        - [1.7.17. Products/GetContainerDropTable](#1717-productsgetcontainerdroptable)
        - [1.7.18. Products/GetLoadoutProducts](#1718-productsgetloadoutproducts)
        - [1.7.19. Products/GetPlayerProducts](#1719-productsgetplayerproducts)
        - [1.7.20. RocketPass/GetPlayerInfo](#1720-rocketpassgetplayerinfo)
        - [1.7.21. RocketPass/GetPlayerPrestigeRewards](#1721-rocketpassgetplayerprestigerewards)
        - [1.7.22. RocketPass/GetRewardContent](#1722-rocketpassgetrewardcontent)
        - [1.7.23. Settings/GetStaticDataURL](#1723-settingsgetstaticdataurl)
        - [1.7.24. Skills/GetPlayerSkill](#1724-skillsgetplayerskill)
        - [1.7.25. Skills/GetSkillLeaderboard](#1725-skillsgetskillleaderboard)
        - [1.7.26. Skills/GetSkillLeaderboardValueForUser](#1726-skillsgetskillleaderboardvalueforuser)
        - [1.7.27. Stats/GetStatLeaderboard](#1727-statsgetstatleaderboard)
        - [1.7.28. Stats/GetStatLeaderboardValueForUser](#1728-statsgetstatleaderboardvalueforuser)
        - [1.7.29. Tournaments/Status/GetTournamentSubscriptions](#1729-tournamentsstatusgettournamentsubscriptions)
    - [1.8. Possible Frequently Asked Questions](#18-possible-frequently-asked-questions)
    - [1.9. Issues / Contributions](#19-issues--contributions)
    - [1.10. Implementations](#110-implementations)

<!-- /TOC -->

## 1.2. Endpoints

The game uses `https://psyonix-rl.appspot.com/Services` to grab configuration values and do authentication.  
When authentication has been successful, it connects to a websocket at `wss://rl-psy.net/ws?PsyConnectionType=Player`.

It is possible to keep using the HTTP api instead of the websocket server. I have not looked at connecting to the websocket server yet, but I assume you send the same headers as you would for an authenticated request for the handshake and then send & receive json requests.

## 1.3. Intercepting requests

If you want to intercept HTTPS requests from the game itself, you have to make sure that the websocket connection fails. It will fallback to HTTPS after 10 failed attempts.

You can easily do this by using the provided [script](rlforcehttps_alt/fiddlerscript.js) for [fiddler](https://www.telerik.com/fiddler).

Make sure you are using a tool that supports HTTPS such as Fiddler / Charles and have installed its `SSL Root Certificate` in your `Trusted Root Certification Authorities`. (Something similar should be done if you are on a mac)

## 1.4. Headers

| Key | Value | Authenticated only |
|-|-|-|
| User-Agent | RL Win/181119.52056.216417 gzip | No |
| PsyBuildID | 1578020590 | No |
| PsyEnvironment | Prod | No |
| PsyRequestID | See [Requests](#17-requests) | No |
| PsySig | See [Signing](#15-signing) | No |
| PsyToken | See [Authentication](#16-authentication) | Yes |
| PsySessionID | See [Authentication](#16-authentication) | Yes |

> Take note that fields like `PsyBuildID`, `FeatureSet` and `GameVersion` may all be changed on a new patch.   
> I will try to keep this repository updated.

## 1.5. Signing

Rocket League uses two HMAC-SHA256 signatures, one for the request and one for the response. Both can be found in the `PsySig` header. The response has an extra header called `PsyTime` which is an unix timestamp.

The input format is just `Unix timestamp, if any, else empty` + `-` + `request body`.

### 1.5.1. Requests

Secret: `c338bd36fb8c42b1a431d30add939fc7`  
Input: `-(Request body)`

### 1.5.2. Responses

Secret: `3b932153785842ac927744b292e40e52`  
Input: `(Value of PsyTime)-(Response body)`

> The secret for `rl-cdn.psyonix.com` is `cqhyz50f3c3j2pxhwo6b1kypxikah0wh` and input `(Response body)`.

## 1.6. Authentication

As of now, I do only know how to implement it for Steam. An example of this can be found in the demo/demo.js file.  
The other platforms should use the same format, just with a different `AuthTicket`.

## 1.7. Requests

All requests have to be send as `POST` with the header `Content-Type: application/x-www-form-urlencoded`.  

If you want to mimic the game as closely as possible, you need to keep track of two counters.

```javascript
var requestIdCounter = 0; // Starts at 0, increments for every request and response.
var serviceIdCounter = 1; // Starts at 1, increments for every service.
```

The result of `requestIdCounter++` should be used for the `PsyRequestID` request header, so it becomes something like `"PsyNetMessage_X_" + requestIdCounter++`.  
The result of `serviceIdCounter++` should be used for the `ID` field below.

A request body looks like this.

```json
[
    {
        "Service": "Settings/GetStaticDataURL",
        "Version": 1,
        "ID": 1,
        "Params": {
            "Platform": "Steam",
            "Language": "INT"
        }
    },
    {
        "Service": "Products/GetPlayerProducts",
        "Version": 1,
        "ID": 2,
        "Params": {
            "PlayerID": "Steam|XXXXXXXXXXXXXXXXXX|0"
        }
    }
]
```

> About all fields like `PlayerID`, its format means `<Platform>|<UniqueId>|<SplitscreenId>`.

### 1.7.1. Auth/AuthPlayer

**Auth:** No  
**Version:** 1  
**Params:** 
```json
{
    "Platform": "Steam",
    "PlayerName": "Your Steam display name",
    "PlayerID": "Your SteamID64",
    "GameVersion": 26,
    "Language": "INT",
    "AuthTicket": "Steam EncryptedAppTicket, see demo/demo.js for an example",
    "BuildRegion": "",
    "FeatureSet": "PrimeUpdate23",
    "bTrial": false,
    "bSkipAuth": false
}
```

### 1.7.2. Clubs/GetClubInvites

**Auth:** Yes  
**Version:** 1  
**Params:** 
```json
{}
```

### 1.7.3. Clubs/GetPlayerClubDetails

**Auth:** Yes  
**Version:** 1  
**Params:** 
```json
{
    "PlayerID": "Steam|XXXXXXXXXXXXXXXXXX|0"
}
```

### 1.7.4. DLC/GetDLC

Gets all available DLC.

**Auth:** Yes  
**Version:** 1  
**Params:** 
```json
{}
```

### 1.7.5. Filters/FilterContent

This is the best call of them all.  
Try it out for yourself.

**Auth:** Yes  
**Version:** 1  
**Params:** 
```json
{
    "Content": [
        "Some name",
        "Another name",
        "More names.."
    ]
}
```

### 1.7.6. GameServer/FindPrivateServer

This call happens when you try to join a private match with name and password.

**Auth:** Yes  
**Version:** 1  
**Params:** 
```json
{
    "ServerName": "SomeName..",
    "Password": "SomePassword.."
}
```

### 1.7.7. GameServer/GetGameServerPingList

Gets all server IPs, ports and their ping.

**Auth:** Yes  
**Version:** 1  
**Params:** 
```json
{}
```

### 1.7.8. GenericStorage/GetPlayerGenericStorage

You have to play with this call yourself a bit, because I don't know if it is useful.  
The response looks pretty boring to me.

All possible categories: MusicPlayerSave_TA, SoundSettingsSave_TA, UISavedValues_TA, MapPrefsSave_TA, RankedReconnectSave_TA, NetworkSave_TA, TutorialSave_TA, BlogTileCache_TA, ProductsSave_TA, PlaylistSkillDataSave_TA, MatchmakingSettingsSave_TA, ClientXPSave_TA, TournamentSettingsSave_TA, SeasonSave_TA, GameplaySettingsSave_TA, ProductsFavoriteSave_TA, ExhibitionMatchSettingsSave_TA, PrivateMatchSettingsSave_TA, ServerBrowserSettingsSave_TA, ProductsOfflineSave_TA, EulaSave_TA, AchievementSave_TA, ProfileGameplaySave_TA, PlayerBannerSave_TA, PlayerAvatarBorderSave_TA, ProfileStatsSave_TA, ProfileControlsSave_TA, ProfileAimAssistSave_TA, ProfileCameraSave_TA, ProfileQuickChatSave_TA, ProfileLoadoutSave_TA, ProfileGamepadSave_TA, ProfilePCSave_TA

**Auth:** Yes  
**Version:** 1  
**Params:** 
```json
{
    "PlayerID": "Steam|XXXXXXXXXXXXXXXXXX|0",
    "Items": [
        {
            "Category": "..",
            "Tick": 0,
            "Checksum": 0
        }
    ]
}
```

### 1.7.9. GenericStorage/SetPlayerGenericStorage

I would be really careful with this one if I were you.

**Auth:** Yes  
**Version:** 1  
**Params:** 
```json
{
    "PlayerID": "Steam|XXXXXXXXXXXXXXXXXX|0",
    "Items": [
        {
            "Category": "..",
            "Tick": 0,
            "Checksum": 0,
            "Data": ".."
        }
    ]
}
```

### 1.7.10. Matchmaking/PlayerCancelPrivateMatch

**Auth:** Yes  
**Version:** 1  
**Params:** 
```json
{}
```

### 1.7.11. Matchmaking/PlayerSearchPrivateMatch

This call happens when creating a private match.

**Auth:** Yes  
**Version:** 1  
**Params:** 
```json
{
    "Region": "EU"
}
```

### 1.7.12. Metrics/RecordMetrics

Why would you use this? :')

### 1.7.13. Microtransaction/ClaimEntitlements

**Auth:** Yes  
**Version:** 1  
**Params:** 
```json
{
    "PlayerID": "Steam|XXXXXXXXXXXXXXXXXX|0",
    "AuthCode": ""
}
```

### 1.7.14. Players/GetChatBanStatus

Pretty self explanatory.

**Auth:** Yes  
**Version:** 1  
**Params:** 
```json
{}
```

### 1.7.15. Players/GetXP

Gets the amount of XP of the given player.

**Auth:** Yes  
**Version:** 1  
**Params:** 
```json
{
    "PlayerID": "Steam|XXXXXXXXXXXXXXXXXX|0"
}
```

### 1.7.16. Population/UpdatePlayerPlaylist

Submits the amount of players in your party and the playlist you are playing.

**Auth:** Yes  
**Version:** 1  
**Params:** 
```json
{
    "Playlist": 0,
    "NumLocalPlayers": 1
}
```

### 1.7.17. Products/GetContainerDropTable

Gets the possible outcome for all crates.

**Auth:** Yes  
**Version:** 2  
**Params:** 
```json
{
    "GameVersion": 25
}
```

### 1.7.18. Products/GetLoadoutProducts

Gets the information of specific product instance ids.

**Auth:** Yes  
**Version:** 1  
**Params:** 
```json
{
    "PlayerID": "Steam|XXXXXXXXXXXXXXXXXX|0",
    "Loadout": [
        "ProductInstanceID",
        "AnotherProductInstanceID",
        "AnotherProductInstanceID.."
    ]
}
```

### 1.7.19. Products/GetPlayerProducts

Gets the inventory of the given player. (Only yourself is allowed)

**Auth:** Yes  
**Version:** 1  
**Params:** 
```json
{
    "PlayerID": "Steam|XXXXXXXXXXXXXXXXXX|0"
}
```

### 1.7.20. RocketPass/GetPlayerInfo

Gets the current tier, premium status and xp multiplier.

**Auth:** Yes  
**Version:** 1  
**Params:** 
```json
{
    "PlayerID": "Steam|XXXXXXXXXXXXXXXXXX|0",
    "RocketPassID": 1
}
```

### 1.7.21. RocketPass/GetPlayerPrestigeRewards

**Auth:** Yes  
**Version:** 1  
**Params:** 
```json
{
    "PlayerID": "Steam|XXXXXXXXXXXXXXXXXX|0",
    "RocketPassID": 1
}
```

### 1.7.22. RocketPass/GetRewardContent

Gets all possible rewards of the ~~battle~~ rocket pass.

**Auth:** Yes  
**Version:** 1  
**Params:** 
```json
{
    "RocketPassID": 1,
    "TierCap": 0
}
```

### 1.7.23. Settings/GetStaticDataURL

The response of this call is actually quite useful.

**Auth:** No  
**Version:** 1  
**Params:** 
```json
{
    "Platform": "Steam",
    "Language": "INT"
}
```

### 1.7.24. Skills/GetPlayerSkill

Gets the ranking information for each ranked playlist of a specific player.

**Auth:** Yes  
**Version:** 1  
**Params:** 
```json
{
    "PlayerID": "Steam|XXXXXXXXXXXXXXXXXX|0"
}
```

### 1.7.25. Skills/GetSkillLeaderboard

Gets the top 100 players for the given playlist.

**Auth:** Yes  
**Version:** 1  
**Params:** 
```json
{
    "Playlist": 10,
    "bDisableCrossPlay": true
}
```

### 1.7.26. Skills/GetSkillLeaderboardValueForUser

Gets the ranking info of a specific player in the given playlist.

**Auth:** Yes  
**Version:** 1  
**Params:** 
```json
{
    "Playlist": 10,
    "PlayerID": "Steam|XXXXXXXXXXXXXXXXXX|0"
}
```

### 1.7.27. Stats/GetStatLeaderboard

Gets the top 100 players for the given stat.

**Auth:** Yes  
**Version:** 1  
**Params:** 
```json
{
    "Stat": "Wins",
    "bDisableCrossPlay": true
}
```

### 1.7.28. Stats/GetStatLeaderboardValueForUser

Gets the ranking info of a specific player in the given stat leaderboard.

**Auth:** Yes  
**Version:** 1  
**Params:** 
```json
{
    "Playlist": 10,
    "PlayerID": "Steam|XXXXXXXXXXXXXXXXXX|0"
}
```

### 1.7.29. Tournaments/Status/GetTournamentSubscriptions

**Auth:** Yes  
**Version:** 1  
**Params:** 
```json
{
    "PlayerID": "Steam|XXXXXXXXXXXXXXXXXX|0"
}
```

## 1.8. Possible Frequently Asked Questions

**Hello, can I make a trade bot with this???**

No, you need more information. But it is definitely possible :')

**Can you help me make one??????**

No.

## 1.9. Issues / Contributions

Feel free to open up an issue for discussion about the API.  
You may also submit a PR to improve the README or the demo.

I would like to keep this repository mostly used for documentation purposes. 

## 1.10. Implementations

None yet.
