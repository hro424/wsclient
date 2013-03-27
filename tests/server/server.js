var ws = require('ws').Server
var server = new ws({
  host : '0.0.0.0',
  port : 8080
});

server.on('connection', function(socket) {
  console.log('connected');
  socket.on('message', function(message) {
    console.log('received: %s', message);
    socket.send(message);
  });
});
