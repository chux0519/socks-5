const net = require('net')
const {createServer, REP} = require('../src/socks5')

// default proxy with logging
const server = createServer({
  onProxy: function defaultProxy (buffer, dist, sock) {
    const client = net.createConnection(dist.port, dist.addr, () => {
      console.log(`${client.localAddress}:${client.localPort} connected to ${dist.addr}:${dist.port}`)
      const rep = Buffer.from(buffer)
      rep[1] = REP.SUCCEED
      sock.write(rep, () => {
        client.pipe(sock)
        sock.pipe(client)

        // logging
        sock.on('data', chunk => {
          console.log(`sent ${chunk.length} bytes to ${dist.addr}:${dist.port}`)
        })
        client.on('data', chunk => {
          console.log(`rcv ${chunk.length} bytes from ${dist.addr}:${dist.port}`)
        })
      })
    })
    client.once('error', console.error)
  }
})

server.listen(1088, () => console.log('listen at 1088'))

// then, test via curl
// curl https://github.com/ --socks5 127.0.0.1:1088
