const colors = require('colors/safe')
const WebSocket = require('ws')
const wss = new WebSocket.Server({
  port: 8124,
  perMessageDeflate: {
    zlibDeflateOptions: {
      chunkSize: 1024,
      memLevel: 7,
      level: 3
    },
    zlibInflateOptions: {
      chunkSize: 10 * 1024
    },
    clientNoContextTakeover: true,
    serverNoContextTakeover: true,
    serverMaxWindowBits: 10,
    concurrencyLimit: 10,
    threshold: 1024
  }
})

function prettyPrint (data, color) {
  let start = data.indexOf('\r\n\r\n')
  if (start !== -1) {
    start += 4
    let dataLen = data.length - start
    if (dataLen === 0) {
      console.log(color('No data was found'))
    } else {
      let jsonString = data.substring(start)
      let jsonPretty = JSON.stringify(JSON.parse(jsonString), null, 2)
      console.log(color(jsonPretty))
    }
  }
}

// A client connected.
wss.on('connection', function (client, req) {
  console.log(req.headers);

  const server = new WebSocket('wss://percon.rl-psy.net/ws?PsyConnectionType=Player', {
    headers: {
      'PsyToken': req.headers['psytoken'],
      'PsySessionID': req.headers['psysessionid'],
      'PsyBuildID': req.headers['psybuildid'],
      'PsyEnvironment': req.headers['psyenvironment'],
      'User-Agent': req.headers['user-agent']
    }
  })

  // We connected to the server.
  server.on('open', function () {
    console.log('Client connected')

    // Proxy from client => server.
    client.on('message', function (message) {
      prettyPrint(message, colors.cyan)
      server.send(message)
    })

    // Proxy from server => client.
    server.on('message', function (message) {
      prettyPrint(message, colors.white)
      client.send(message)
    })
  })
})

console.log('Running proxy on 127.0.0.1:8124')
