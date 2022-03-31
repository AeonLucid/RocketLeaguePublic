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
        - [1.7.1. Ads/GetAds](#171-adsgetads)
        - [1.7.2. Auth/AuthPlayer (STEAM)](#172-authauthplayer-steam)
        - [1.7.2. Auth/AuthPlayer (EPIC)](#172-authauthplayer-epic)
        - [1.7.3. Clubs/GetClubInvites](#173-clubsgetclubinvites)
        - [1.7.4. Clubs/GetPlayerClubDetails](#174-clubsgetplayerclubdetails)
        - [1.7.5. Codes/RedeemCode](#175-codesredeemcode)
        - [1.7.6. DLC/GetDLC](#176-dlcgetdlc)
        - [1.7.7. Filters/FilterContent](#177-filtersfiltercontent)
        - [1.7.8. GameServer/FindPrivateServer](#178-gameserverfindprivateserver)
        - [1.7.9. GameServer/GetGameServerPingList](#179-gameservergetgameserverpinglist)
        - [1.7.10. GenericStorage/GetPlayerGenericStorage](#1710-genericstoragegetplayergenericstorage)
        - [1.7.11. GenericStorage/SetPlayerGenericStorage](#1711-genericstoragesetplayergenericstorage)
        - [1.7.12. Matchmaking/PlayerCancelPrivateMatch](#1712-matchmakingplayercancelprivatematch)
        - [1.7.13. Matchmaking/PlayerSearchPrivateMatch](#1713-matchmakingplayersearchprivatematch)
        - [1.7.14. Metrics/RecordMetrics](#1714-metricsrecordmetrics)
        - [1.7.15. Microtransaction/ClaimEntitlements](#1715-microtransactionclaimentitlements)
        - [1.7.16. Players/GetChatBanStatus](#1716-playersgetchatbanstatus)
        - [1.7.17. Players/GetXP](#1717-playersgetxp)
        - [1.7.18. Population/UpdatePlayerPlaylist](#1718-populationupdateplayerplaylist)
        - [1.7.19. Products/GetContainerDropTable](#1719-productsgetcontainerdroptable)
        - [1.7.20. Products/GetLoadoutProducts](#1720-productsgetloadoutproducts)
        - [1.7.21. Products/GetPlayerProducts](#1721-productsgetplayerproducts)
        - [1.7.22. RocketPass/GetPlayerInfo](#1722-rocketpassgetplayerinfo)
        - [1.7.23. RocketPass/GetPlayerPrestigeRewards](#1723-rocketpassgetplayerprestigerewards)
        - [1.7.24. RocketPass/GetRewardContent](#1724-rocketpassgetrewardcontent)
        - [1.7.25. Settings/GetStaticDataURL](#1725-settingsgetstaticdataurl)
        - [1.7.26. Skills/GetPlayerSkill](#1726-skillsgetplayerskill)
        - [1.7.27. Skills/GetSkillLeaderboard](#1727-skillsgetskillleaderboard)
        - [1.7.28. Skills/GetSkillLeaderboardValueForUser](#1728-skillsgetskillleaderboardvalueforuser)
        - [1.7.29. Stats/GetStatLeaderboard](#1729-statsgetstatleaderboard)
        - [1.7.30. Stats/GetStatLeaderboardValueForUser](#1730-statsgetstatleaderboardvalueforuser)
        - [1.7.31. Tournaments/Status/GetTournamentSubscriptions](#1731-tournamentsstatusgettournamentsubscriptions)
    - [1.8. Possible Frequently Asked Questions](#18-possible-frequently-asked-questions)
    - [1.9. Issues / Contributions](#19-issues--contributions)
    - [1.10. Implementations](#110-implementations)

<!-- /TOC -->

## 1.2. Endpoints

The game uses `https://api.rlpp.psynet.gg/Services` to grab configuration values and do authentication.  
When authentication has been successful, it connects to a websocket at `wss://rl-psy.net/ws?PsyConnectionType=Player`.

It is possible to keep using the HTTP api instead of the websocket server. I have not looked at connecting to the websocket server yet, but I assume you send the same headers as you would for an authenticated request for the handshake and then send & receive json requests.

## 1.3. Intercepting requests

If you want to intercept HTTPS requests from the game itself, you have to make sure that the websocket connection fails. It will fallback to HTTPS after 10 failed attempts.

You can easily do this by using the provided [script](rlforcehttps_fiddler/fiddlerscript.js) for [fiddler](https://www.telerik.com/fiddler).

Make sure you are using a tool that supports HTTPS such as Fiddler / Charles and have installed its `SSL Root Certificate` in your `Trusted Root Certification Authorities`. (Something similar should be done if you are on a mac)

## 1.4. Headers

| Key | Value | Authenticated only |
|-|-|-|
| User-Agent | RL Win/220128.58061.363257 gzip | No |
| PsyBuildID | -960700785 | No |
| PsyEnvironment | Prod | No |
| PsyRequestID | See [Requests](#17-requests) | No |
| PsySig | See [Signing](#15-signing) | No |
| PsyToken | See [Authentication](#16-authentication) | Yes |
| PsySessionID | See [Authentication](#16-authentication) | Yes |

> Take note that fields like `PsyBuildID`, `FeatureSet` and `GameVersion` may all be changed on a new patch.   
> I will try to keep this repository updated.

You can find the most up-to-date values for these variables by reading the `launch.log` file generated by Rocket League. On windows with Steam, this file can be found in `Documents\My Games\Rocket League\TAGame\Logs`.

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

### 1.7.1. Ads/GetAds

**Auth:** Yes
**Version:** 1
**Params:**
```json
{
    "Language": "INT"
}
```
**Result:**
```json
{
  "Ads": [
    {
      "ZoneID": 201,
      "Url": "https://rl-cdn.psyonix.com/Ads/Prod/124.7CjfwUcy/201.jpg",
      "UTCEndTime": 0000000000
    },
    {
      "ZoneID": 202,
      "Url": "https://rl-cdn.psyonix.com/Ads/Prod/124.7CjfwUcy/202.jpg",
      "UTCEndTime": 0000000000
    },
    {
      "ZoneID": 403,
      "Url": "https://rl-cdn.psyonix.com/Ads/Prod/124.7CjfwUcy/403.jpg",
      "UTCEndTime": 0000000000
    },
    {
      "ZoneID": 404,
      "Url": "https://rl-cdn.psyonix.com/Ads/Prod/124.7CjfwUcy/404.jpg",
      "UTCEndTime": 0000000000
    }
  ]
}
```
> The ZoneIDs may look like status codes, but are actually the id used to match the corresponding advert location, like the billboards.

### 1.7.2. Auth/AuthPlayer Steam

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
    "FeatureSet": "PrimeUpdate36_2",
    "bTrial": false,
    "bSkipAuth": false
}
```
**Result:**
```json
{
    "SessionID": "sessionid", 
    "VerifiedPlayerName": "name", 
    "UseWebSocket": true, 
    "PerConURL": "url", 
    "PsyTag": {
        "Name": "name", 
        "Code": 0000
    }, 
    "CountryRestrictions": ["KeyCrate"]
}
```

### 1.7.2. Auth/AuthPlayer Epic

**Auth:** No  
**Version:** 2  
**Params:** 
```json
{
    "Platform": "Epic",
    "PlayerName": "Your Epic display name",
    "PlayerID": "Your Epic ID",
    "Language": "INT",
    "AuthTicket": "Epic EncryptedAppTicket, see demo/demo.js for an example",
    "BuildRegion": "",
    "FeatureSet": "PrimeUpdate36_2",
    "bTrial": false,
    "bSkipAuth": false,
    "bSetAsPrimaryAccount": false,
    "EpicAuthTicket": "Same as AuthTicket",
    "EpicAccountID": "Same as PlayerID"
}
```
**Result:**
```json
{
    "SessionID": "sessionid",
    "VerifiedPlayerName": "name",
    "UseWebSocket": true,
    "PerConURL": "url",
    "PerConURLv2": "url version 2",
    "PsyToken": "Token",
    "PsyTag": {
      "Name": "name",
      "Code": 0000
    },
    "IsLastChanceAuthBan": false,
    "CountryRestrictions": []
}
```

### 1.7.3. Clubs/GetClubInvites

**Auth:** Yes  
**Version:** 1  
**Params:** 
```json
{}
```
**Result:**
```json
{
    "ClubInvites": []
}
```

### 1.7.4. Clubs/GetPlayerClubDetails

**Auth:** Yes  
**Version:** 2
**Params:** 
```json
{
    "PlayerID": "Steam|XXXXXXXXXXXXXXXXXX|0"
}
```
**Result:**
```json
{
    "ClubDetails": {
        "ClubID": 0000,
        "ClubName": "name",
        "ClubTag": "name",
        "MOTD": "desc",
        "PrimaryColor": -10092527,
        "AccentColor": -32816,
        "OwnerPlayerID": "Steam|XXXXXXXXXXXXXXXXXX|0",
        "Members": [
            {
                "PlayerID": "Steam|XXXXXXXXXXXXXXXXXX|0",
                "PlayerName": "name",
                "RoleName": "Owner",
                "CreatedTime": "1535573427",
                "DeletedTime": 0
            },
            {
                "PlayerID": "Steam|XXXXXXXXXXXXXXXXXX|0",
                "PlayerName": "name",
                "RoleName": "Member",
                "CreatedTime": "1535575218",
                "DeletedTime": 0
            }
        ],
        "Flags": [],
        "bVerified": false,
        "CreatedTime": 1535573413,
        "LastUpdatedTime": 1562620061,
        "NameLastUpdatedTime": 0,
        "DeletedTime": 0
    }
}

```

### 1.7.5. Codes/RedeemCode

Attempts to redeem a code.

**Auth:** Yes  
**Version:** 2  
**Params:** 
```json
{
  "Code": "CODE",
  "PlayerID": "Steam|XXXXXXXXXXXXXXXXXX|0"
}
```
**Result if successful:**
```json
{
  "Result": {
    "Drops": [
      {
        "ProductID": "2879",
        "InstanceID": "00000000000000000000000579ed4c93",
        "Attributes": [],
        "SeriesID": 30,
        "AddedTimestamp": 1645825416,
        "UpdatedTimestamp": 1645825416
      }
    ]
  }
}
```
**Result if code has already been claimed:**
```json
{
  "Error": {
    "Type": "CodeHasBeenRedeemed",
    "Message": ""
  }
}
```
**Result if not valid:**
```json
{
  "Error": {
    "Type": "CodeIsNotValid",
    "Message": ""
  }
}
```

### 1.7.6. DLC/GetDLC

Gets all available DLC.

**Auth:** Yes  
**Version:** 1  
**Params:** 
```json
{}
```
**Result:**
```json
{
    "DLC": []
}
```
### 1.7.7. Filters/FilterContent


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
**Result:**
```json
{
    "FilteredContent": [
        "Some name",
        "Another name",
        "More names.."
    ]
}
```

### 1.7.8. GameServer/FindPrivateServer

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
**Result:**
```json
{
    "Servers": []
}
```

### 1.7.9. GameServer/GetGameServerPingList

Gets all server IPs, ports and their ping.

**Auth:** Yes  
**Version:** 1  
**Params:** 
```json
{}
```
**Result:**
```json
{
    "Servers": [
        {
            "Region": "ASC",
            "Host": "ip43-239-136-105.datahound.com",
            "Port": "7830"
        },
        {
            "Region": "ASM",
            "Host": "ip103-23-210-172.datahound.com",
            "Port": "7838"
        }
    ]
}
```

### 1.7.10. GenericStorage/GetPlayerGenericStorage

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
**Result:**
```json
{
    "Items": [
        {
            "Category": "..",
            "Data": "..",
            "Tick": 1,
            "Checksum": "43523452345",
            "bChecksumMatch": false
        }
    ]
}
```

### 1.7.11. GenericStorage/SetPlayerGenericStorage

I would be really careful with this one if I were you.

**Auth:** Yes  
**Version:** 2  
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

### 1.7.12. Matchmaking/PlayerCancelPrivateMatch

**Auth:** Yes  
**Version:** 1  
**Params:** 
```json
{}
```
**Result:**
```json
{}
```

### 1.7.13. Matchmaking/PlayerSearchPrivateMatch

This call happens when creating a private match.

**Auth:** Yes  
**Version:** 2  
**Params:** 
```json
{
    "Region": "EU"
}
```
**Result:**
```json
{}
```

### 1.7.14. Metrics/RecordMetrics

Why would you use this? :')

### 1.7.15. Microtransaction/ClaimEntitlements

**Auth:** Yes  
**Version:** 2  
**Params:** 
```json
{
    "PlayerID": "Steam|XXXXXXXXXXXXXXXXXX|0",
    "AuthCode": ""
}
```
**Result:**
```json
{
    "Products": []
}
```

### 1.7.16. Players/GetChatBanStatus

Pretty self explanatory.

**Auth:** Yes  
**Version:** 1  
**Params:** 
```json
{}
```
**Result:**
```json
{
    "BannedUntil": 0,
    "BannedMessage": null,
    "BannedCitations": null,
    "bPermanentlyBanned": false,
    "bContributedToBan": false
}
```

### 1.7.17. Players/GetXP

Gets the amount of XP of the given player.

**Auth:** Yes  
**Version:** 1  
**Params:** 
```json
{
    "PlayerID": "Steam|XXXXXXXXXXXXXXXXXX|0"
}
```
**Result:**
```json
{
    "XPInfoResponse": {
        "TotalXP": 536436546456356,
        "XPLevel": 642,
        "XPTitle": "",
        "XPProgressInCurrentLevel": 1501,
        "XPRequiredForNextLevel": 20000
    }
}
```

### 1.7.18. Population/UpdatePlayerPlaylist

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
**Result:**
```json
{}
```

### 1.7.19. Products/GetContainerDropTable

Gets the possible outcome for all crates.

**Auth:** Yes  
**Version:** 2  
**Params:** 
```json
{
    "GameVersion": 25
}
```

### 1.7.20. Products/GetLoadoutProducts

Gets the information of specific product instance ids.

**Auth:** Yes  
**Version:** 2  
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
**Result:**
```json
{
    "ProductData": []
}
```

### 1.7.21. Products/GetPlayerProducts

Gets the inventory of the given player. (Only yourself is allowed)

**Auth:** Yes  
**Version:** 2  
**Params:** 
```json
{
    "PlayerID": "Steam|XXXXXXXXXXXXXXXXXX|0"
}
```
**Result:**
```json
{
    "ProductData": [
        {
            "ProductID": 2363,
            "InstanceID": "6456765456",
            "Attributes": [],
            "SeriesID": 19,
            "AddedTimestamp": 1514740692,
            "UpdatedTimestamp": 1514740692,
            "TradeHold": -2
        }
    ]
}
```

### 1.7.22. RocketPass/GetPlayerInfo

Gets the current tier, premium status and xp multiplier.

**Auth:** Yes  
**Version:** 2  
**Params:** 
```json
{
    "PlayerID": "Steam|XXXXXXXXXXXXXXXXXX|0",
    "RocketPassID": 1
}
```

### 1.7.23. RocketPass/GetPlayerPrestigeRewards

**Auth:** Yes  
**Version:** 1  
**Params:** 
```json
{
    "PlayerID": "Steam|XXXXXXXXXXXXXXXXXX|0",
    "RocketPassID": 1
}
```
**Result:**
```json
{
    "PrestigeRewards": [
        {
            "Tier": 71,
            "ProductData": [
                {
                    "ProductID": 3316,
                    "InstanceID": null,
                    "Attributes": [],
                    "SeriesID": 44,
                    "AddedTimestamp": null,
                    "UpdatedTimestamp": null
                }
            ],
            "RewardDrops": [],
            "CurrencyDrops": [],
            "ContainerDrops": []
        }
    ]
}
```

### 1.7.24. RocketPass/GetRewardContent

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
**Result:**
```json
{
    "TierCap": 70,
    "FreeRewards": [
        {
            "Tier": 1,
            "ProductData": [],
            "XPRewards": [],
            "CurrencyDrops": []
        }
    ],
    "PremiumRewards": [
        {
            "Tier": 1,
            "ProductData": [
                {
                    "ProductID": "3155",
                    "InstanceID": null,
                    "Attributes": [],
                    "SeriesID": 39,
                    "AddedTimestamp": null,
                    "UpdatedTimestamp": null
                }
            ],
            "XPRewards": [],
            "CurrencyDrops": []
        }
    ]
}
```

### 1.7.25. Settings/GetStaticDataURL

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
**Result:**
```json
{
    "URL": "http://psyonix-rl.appspot.com/Static.json?BuildID=-1878310188&Platform=Steam&Language=INT&Environment=Prod"
}
```

### 1.7.26. Skills/GetPlayerSkill

Gets the ranking information for each ranked playlist of a specific player.

**Auth:** Yes  
**Version:** 1  
**Params:** 
```json
{
    "PlayerID": "Steam|XXXXXXXXXXXXXXXXXX|0"
}
```
**Result:**
```json
{
    "Skills": [
        {
            "Playlist": 0,
            "Mu": 42.3449,
            "Sigma": 2.8337,
            "Tier": 0,
            "Division": 0,
            "MMR": 42.3449,
            "WinStreak": 1,
            "MatchesPlayed": 0
        },
        {
            "Playlist": 10,
            "Mu": 25.6839,
            "Sigma": 8.13958,
            "Tier": 0,
            "Division": 0,
            "MMR": 25.6839,
            "WinStreak": 1,
            "MatchesPlayed": 0
        },
        {
            "Playlist": 11,
            "Mu": 45.2342,
            "Sigma": 3.5,
            "Tier": 0,
            "Division": 0,
            "MMR": 45.2342,
            "WinStreak": -1,
            "MatchesPlayed": 0
        },
        {
            "Playlist": 13,
            "Mu": 45.5141,
            "Sigma": 3.23682,
            "Tier": 0,
            "Division": 0,
            "MMR": 45.5141,
            "WinStreak": 2,
            "MatchesPlayed": 7
        },
        {
            "Playlist": 27,
            "Mu": 38.5532,
            "Sigma": 3.59969,
            "Tier": 0,
            "Division": 0,
            "MMR": 38.5532,
            "WinStreak": -5,
            "MatchesPlayed": 0
        },
        {
            "Playlist": 28,
            "Mu": 22.6323,
            "Sigma": 6.88745,
            "Tier": 0,
            "Division": 0,
            "MMR": 22.6323,
            "WinStreak": 1,
            "MatchesPlayed": 0
        },
        {
            "Playlist": 30,
            "Mu": 44.6283,
            "Sigma": 4.79466,
            "Tier": 0,
            "Division": 0,
            "MMR": 44.6283,
            "WinStreak": -5,
            "MatchesPlayed": 0
        }
    ],
    "RewardLevels": {
        "SeasonLevel": 0,
        "SeasonLevelWins": 5
    }
}
```

### 1.7.27. Skills/GetSkillLeaderboard

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

### 1.7.28. Skills/GetSkillLeaderboardValueForUser

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
**Result:**
```json
{
    "LeaderboardID": "Skill10",
    "bHasSkill": true,
    "MMR": 25.6839,
    "Value": 0
}
```

### 1.7.29 Stats/GetStatLeaderboard

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

### 1.7.30. Stats/GetStatLeaderboardValueForUser

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

### 1.7.31. Tournaments/Status/GetTournamentSubscriptions

**Auth:** Yes  
**Version:** 1  
**Params:** 
```json
{
    "PlayerID": "Steam|XXXXXXXXXXXXXXXXXX|0"
}
```
**Result:**
```json
{
    "CreatorOf": [],
    "Registered": [],
    "Tournaments": []
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
