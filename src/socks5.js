const net = require('net')

// https://www.ietf.org/rfc/rfc1928.txt

// constants

const VER = 0x05

// methods
const METHODS = {
  NO_AUTHENTICATION_REQUIRED: 0x00,
  USERNAME_PASSWORD: 0x02,
  NO_ACCEPTABLE_METHODS: 0xff
}

// username/password subnegotiation status
const STATUS = {
  SUCCESS: 0x00,
  FAILURE: 0xff
}

// command
const CMD = {
  CONNECT: 0x01
}

const RSV = 0x00

const ATYPE = {
  IP_V4: 0x01,
  DOMAIN_NAME: 0x03,
  IP_V6: 0x04
}

const REP = {
  SUCCEED: 0x00
}

function createServer (options = {}) {
  const {
    onProxy = defaultProxy,
    username,
    password
  } = options

  const socks = []

  // create local server
  const local = net.createServer(sock => {
    sock.on('error', console.error)
    sock.once('data', connect)
    sock.once('end', () => socks.splice(socks.indexOf(sock), 1))

    // connect
    // +----+----------+----------+
    // |VER | NMETHODS | METHODS  |
    // +----+----------+----------+
    // | 1  |    1     | 1 to 255 |
    // +----+----------+----------+
    function connect (buffer) {
      if (!checkVersion(buffer) || buffer[1] === 0 /* nmethods */) return sock.end()
      if (username && password) {
        sock.write(Buffer.from([VER, METHODS.USERNAME_PASSWORD]), () => {
          sock.once('data', authenticate)
        })
      } else {
        // if no username and password pass in, treat as no authentication
        sock.write(Buffer.from([VER, METHODS.NO_AUTHENTICATION_REQUIRED]), () => {
          sock.once('data', serve)
        })
      }
    }

    // authenticate (username/password only)
    // +----+------+----------+------+----------+
    // |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
    // +----+------+----------+------+----------+
    // | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
    // +----+------+----------+------+----------+
    function authenticate (buffer) {
      if (buffer[0] !== 0x01 /* subnegotiation version */) return sock.end()
      const uLen = buffer[1]
      const user = buffer.toString('utf8', 2, 2 + uLen)
      const pLen = buffer[uLen + 2]
      const pass = buffer.toString('utf8', uLen + 3, uLen + 3 + pLen)
      if (username === user && password === pass) {
        sock.write(Buffer.from([VER, STATUS.SUCCESS]), () => {
          sock.once('data', serve)
        })
      } else {
        sock.write(Buffer.from([VER, STATUS.FAILURE]))
      }
    }

    // serve cmd
    // +----+-----+-------+------+----------+----------+
    // |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    // +----+-----+-------+------+----------+----------+
    // | 1  |  1  | X'00' |  1   | Variable |    2     |
    // +----+-----+-------+------+----------+----------+

    function serve (buffer) {
      socks.push(sock)
      if (!checkVersion(buffer) || buffer[1] !== CMD.CONNECT || buffer[2] !== RSV) {
        return sock.end()
      }
      const dist = getDistInfo(buffer)
      if (!dist) {
        return sock.end()
      }
      onProxy(buffer, dist, sock)
    }
  })

  return local
}

function checkVersion (buf) {
  return buf.length >= 2 && buf[0] === VER
}

function getDistInfo (buffer) {
  switch (buffer[3]) {
    case ATYPE.IP_V4:
      return {
        addr: `${buffer[4]}.${buffer[5]}.${buffer[6]}.${buffer[7]}`,
        port: buffer.readUInt16BE(8)
      }
    case ATYPE.DOMAIN_NAME:
      const len = buffer[4]
      return {
        addr: buffer.toString('utf8', 5, 5 + len),
        port: buffer.readUInt16BE(5 + len)
      }
    case ATYPE.IP_V6:
      return {
        addr: buffer.slice(buffer[4], buffer[20]),
        port: buffer.readUInt16BE(20)
      }
    default:
  }
}

function defaultProxy (buffer, dist, sock) {
  const client = net.createConnection(dist.port, dist.addr, () => {
    const rep = Buffer.from(buffer)
    rep[1] = REP.SUCCEED
    sock.write(rep, () => {
      client.pipe(sock)
      sock.pipe(client)
    })
  })
  client.once('error', console.error)
}

module.exports = {
  createServer,
  checkVersion,
  getDistInfo,
  VER,
  METHODS,
  CMD,
  RSV,
  ATYPE,
  REP
}
