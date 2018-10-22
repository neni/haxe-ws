package haxe.net.impl;

import haxe.crypto.Base64;
import haxe.crypto.Sha1;
import haxe.io.Bytes;
import haxe.net.Socket2;
import haxe.net.WebSocket.ReadyState;


class WebSocketGeneric extends WebSocket {

    private var socket:Socket2;
    private var origin = "http://127.0.0.1/";
    private var scheme = "ws";
    private var key = "";
    private var host = "127.0.0.1";
    private var port = 80;
    public var path(default, null) = "/";
    private var secure = false;
    private var protocols = [];
    private var state = State.Handshake;
    private var needHandleData:Bool = false;

    function initialize(uri:String, protocols:Array<String> = null, origin:String = null, key:String = "") {
      if (origin == null) origin = "http://127.0.0.1/";
      this.protocols = protocols;
      this.origin = origin;
      this.key = (key!="" && key!=null)? key : this.getRandomKey();
      var reg = ~/^(\w+?):\/\/([\w\.-]+)(:(\d+))?(\/.*)?$/;
      //var reg = ~/^(\w+?):/;
      if (!reg.match(uri)) throw 'Uri not matching websocket uri "${uri}"';
      scheme = reg.matched(1);
      switch (scheme) {
          case "ws": secure = false;
          case "wss": secure = true;
          default: throw 'Scheme "${scheme}" is not a valid websocket scheme';
      }
      host = reg.matched(2);
      port = (reg.matched(4) != null) ? Std.parseInt(reg.matched(4)) : (secure ? 443 : 80);
      path = reg.matched(5);
      if (path == null) path = '/';

      socket = Socket2.create(host, port, secure, debug);
      state = State.Handshake;
      socket.onconnect = function() {
        #if debug
          _debug('socket connected');
        #end
        writeBytes(prepareClientHandshake(path, host, port, this.key, origin));
        //this.onopen();
      };
      commonInitialize();

      return this;
    }


    function commonInitialize() {
      socketData = new BytesRW();
      socket.onclose = function() {
        #if debug
          _debug('socket closed');
        #end
        setClosed();
      };
      socket.onerror = function() {
        #if debug
          _debug('ioerror: ');
        #end
        this.onerror('error');
      };
      socket.ondata = function(data:Bytes) {
        socketData.writeBytes(data);
        handleData();
      };
    }


    public static function create(uri:String, protocols:Array<String> = null, origin:String = null, key:String = "") {
      return new WebSocketGeneric().initialize(uri, protocols, origin, key);
    }


    public static function createFromAcceptedSocket(socket:Socket2, alreadyRecieved:String = '') {
      var websocket = new WebSocketGeneric();
      websocket.socket = socket;
      websocket.commonInitialize();
      websocket.state = State.ServerHandshake;
      websocket.httpHeader = alreadyRecieved;
      websocket.needHandleData = true;
      return websocket;
    }


    override public function process() {
      socket.process();
      if (needHandleData) {
        handleData();
      }
    }


    #if debug
    private function _debug(msg:String, ?p:PosInfos):Void {
      haxe.Log.trace(msg, p);
    }
    #end


    private function writeBytes(data:Bytes) {
      //if (socket == null || !socket.connected) return;
      try {
        socket.send(data);
      } catch (e:Dynamic) {
        trace(e);
        onerror(Std.string(e));
      }
    }


    private var socketData:BytesRW;
    private var isFinal:Bool;
    private var isMasked:Bool;
    private var opcode:Opcode;
    private var frameIsBinary:Bool;
    private var partialLength:Int;
    private var length:Int;
    private var mask:Bytes;
    private var httpHeader:String = "";
    private var lastPong:Date = null;
    private var payload:BytesRW = null;


    private function handleData() {
      needHandleData = false;

      while (true) {
          if (payload == null) payload = new BytesRW();

          switch (state) {

            case State.Handshake:
              if (!readHttpHeader()) {
                return;
              }
              state = State.Head;
              this.onopen();

            case State.ServerHandshake:
              if (!readHttpHeader()) {
                return;
              }
              try {
                var handshake = prepareServerHandshake();
                #if debug
                  _debug('Sending responce: $handshake');
                #end
                writeBytes(Bytes.ofString(handshake));
                state = State.Head;
                this.onopen();
              }catch (e:String) {
                writeBytes(Bytes.ofString(prepareHttp400(e)));
                #if debug
                  _debug('Error in http request: $e');
                #end
                socket.close();
                state = State.Closed;
              }

            case State.Head:
              if (socketData.available < 2) return;
              var b0 = socketData.readByte();
              var b1 = socketData.readByte();
              isFinal = ((b0 >> 7) & 1) != 0;
              opcode = cast(((b0 >> 0) & 0xF), Opcode);
              frameIsBinary = if (opcode == Opcode.Text) false; else if (opcode == Opcode.Binary) true; else frameIsBinary;
              partialLength = ((b1 >> 0) & 0x7F);
              isMasked = ((b1 >> 7) & 1) != 0;
              state = State.HeadExtraLength;

            case State.HeadExtraLength:
              if (partialLength == 126) {
                if (socketData.available < 2) return;
                length = socketData.readUnsignedShort();
              } else if (partialLength == 127) {
                if (socketData.available < 8) return;
                var tmp = socketData.readUnsignedInt();
                if(tmp != 0) throw 'message too long';
                length = socketData.readUnsignedInt();
              } else {
                length = partialLength;
              }
              state = State.HeadExtraMask;

            case State.HeadExtraMask:
              if (isMasked) {
                if (socketData.available < 4) return;
                mask = socketData.readBytes(4);
              }
              state = State.Body;

            case State.Body:
              if (socketData.available < length) return;
              payload.writeBytes(socketData.readBytes(length));
              if(state != State.Closed) state = State.Head;
              switch (opcode) {
                case Opcode.Binary | Opcode.Text | Opcode.Continuation:
                  #if debug
                    _debug("Received message, " + "Type: " + opcode);
                  #end
                  if (isFinal) {
                    var messageData = payload.readAllAvailableBytes();
                    var unmakedMessageData = (isMasked) ? applyMask(messageData, mask) : messageData;
                    if (frameIsBinary) {
                      this.onmessageBytes(unmakedMessageData);
                    } else {
                      this.onmessageString(Utf8Encoder.decode(unmakedMessageData));
                    }
                    payload = null;
                  }
                case Opcode.Ping:
                  #if debug
                    _debug("Received Ping");
                  #end
                  //onPing.dispatch(null);
                  sendFrame(payload.readAllAvailableBytes(), Opcode.Pong);
                case Opcode.Pong:
                  #if debug
                    _debug("Received Pong");
                  #end
                  //onPong.dispatch(null);
                  lastPong = Date.now();
                case Opcode.Close:
                  #if debug
                    _debug("Socket Closed");
                  #end
                  setClosed();
                  try {
                      socket.close();
                  } catch(_:Dynamic) {}
              }

            default:
              return;
          }
      }

      //trace('data!' + socket.bytesAvailable);
      //trace(socket.readUTFBytes(socket.bytesAvailable));
    }


    private function setClosed() {
      if (state != State.Closed) {
        state = State.Closed;
        onclose();
      }
    }


    private function ping() {
      sendFrame(Bytes.alloc(0), Opcode.Ping);
    }


    private function isHttpHeaderRead():Bool {
      return httpHeader.substr( -4) == "\r\n\r\n";
    }


    private function readHttpHeader():Bool {
      while (!isHttpHeaderRead() && socketData.available > 0) {
        httpHeader += String.fromCharCode(socketData.readByte());
      }
      return isHttpHeaderRead();
    }

    private function prepareServerHandshake() {
      #if debug
        trace('HTTP request: \n$httpHeader');
      #end

      var requestLines = httpHeader.split('\r\n');
      requestLines.pop();
      requestLines.pop();

      var firstLine = requestLines.shift();
      var regexp = ~/^GET (.*) HTTP\/1.1$/;
      if (!regexp.match(firstLine)) throw 'First line of HTTP request is invalid: "$firstLine"';
      path = regexp.matched(1);


      var acceptKey:String = {
        var key:String = null;
        var version:String = null;
        var upgrade:String = null;
        var connection:String = null;
        var regexp = ~/^(.*): (.*)$/;
        for (header in requestLines) {
          if (!regexp.match(header)) throw 'HTTP request line is invalid: "$header"';
          var name = regexp.matched(1);
          var value = regexp.matched(2);
          switch(name) {
            case 'Sec-WebSocket-Key': key = value;
            case 'Sec-WebSocket-Version': version = value;
            case 'Upgrade': upgrade = value;
            case 'Connection': connection = value;
          }
        }

        if (
          version != '13'
          || upgrade != 'websocket'
          || connection.indexOf('Upgrade') < 0
          || key == null
        ) {
          throw [
            '"Sec-WebSocket-Version" is "$version", should be 13',
            '"upgrade" is "$upgrade", should be "websocket"',
            '"Sec-WebSocket-Key" is "$key", should be present'
          ].join('\n');
        }

        Base64.encode(Sha1.make(Bytes.ofString(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')));
      }

      if (debug) trace('Websocket succefully connected');

      return [
        'HTTP/1.1 101 Switching Protocols',
        'Upgrade: websocket',
        'Connection: Upgrade',
        'Sec-WebSocket-Accept: $acceptKey',
        '',    ''
      ].join('\r\n');

    }


    private function prepareHttp400(message:String) {
      return [
        'HTTP/1.1 400 Bad request',
        '',
        '<h1>HTTP 400 Bad request</h1>',
        message
      ].join('\r\n');
    }


    private function prepareClientHandshake(url:String, host:String, port:Int, key:String, origin:String):Bytes {
      var lines = [];
      lines.push('GET ${url} HTTP/1.1');
      lines.push('Host: ${host}:${port}');
      lines.push('Pragma: no-cache');
      lines.push('Cache-Control: no-cache');
      lines.push('Upgrade: websocket');
      if (this.protocols != null) {
          lines.push('Sec-WebSocket-Protocol: ' + this.protocols.join(', '));
      }
      lines.push('Sec-WebSocket-Version: 13');
      lines.push('Connection: Upgrade');
      lines.push("Sec-WebSocket-Key: " + Base64.encode(Utf8Encoder.encode(key)));
      lines.push('Origin: ${origin}');
      lines.push('User-Agent: Mozilla/5.0');

      return Utf8Encoder.encode(lines.join("\r\n") + "\r\n\r\n");
    }


    override public function close() {
      if(state != State.Closed) {
        sendFrame(Bytes.alloc(0), Opcode.Close);
        socket.close();
        setClosed();
      }
    }


    private function sendFrame(data:Bytes, type:Opcode) {
      writeBytes(prepareFrame(data, type, true));
    }


    override function get_readyState():ReadyState {
      return switch(state) {
        case Handshake: ReadyState.Connecting;
        case ServerHandshake: ReadyState.Connecting;
        case Head: ReadyState.Open;
        case HeadExtraLength: ReadyState.Open;
        case HeadExtraMask: ReadyState.Open;
        case Body: ReadyState.Open;
        case Closed: ReadyState.Closed;
      }
    }


    override public function sendString(message:String) {
      if (readyState != Open){
        throw('websocket not open');
      }
      sendFrame(Utf8Encoder.encode(message), Opcode.Text);
    }


    override public function sendBytes(message:Bytes) {
      if (readyState != Open) throw('websocket not open');
      sendFrame(message, Opcode.Binary);
    }


    static private function generateMask() {
      var maskData = Bytes.alloc(4);
      maskData.set(0, Std.random(256));
      maskData.set(1, Std.random(256));
      maskData.set(2, Std.random(256));
      maskData.set(3, Std.random(256));
      return maskData;
    }


    static private function applyMask(payload:Bytes, mask:Bytes) {
      var maskedPayload = Bytes.alloc(payload.length);
      for (n in 0 ... payload.length) maskedPayload.set(n, payload.get(n) ^ mask.get(n % mask.length));
      return maskedPayload;
    }


    private function prepareFrame(data:Bytes, type:Opcode, isFinal:Bool):Bytes {
      var out = new BytesRW();

      //Chrome: VM321:1 WebSocket connection to 'ws://localhost:8000/' failed: A server must not mask any frames that it sends to the client.
      var isMasked = true; //false; // All clientes messages must be masked: http://tools.ietf.org/html/rfc6455#section-5.1
      var mask = generateMask();
      var sizeMask = (isMasked ? 0x80 : 0x00);

      out.writeByte(type.toInt() | (isFinal ? 0x80 : 0x00));

      if (data.length < 126) {
        out.writeByte(data.length | sizeMask);
      } else if (data.length < 65536) {
        out.writeByte(126 | sizeMask);
        out.writeShort(data.length);
      } else {
        out.writeByte(127 | sizeMask);
        out.writeInt(0);
        out.writeInt(data.length);
      }

      if (isMasked) out.writeBytes(mask);

      out.writeBytes(isMasked ? applyMask(data, mask) : data);
      return out.readAllAvailableBytes();
    }


    private function getRandomKey():String {
      var chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
      var key = "";
      for (i in 0...10) key += chars.charAt(Std.int(Math.random() * chars.length));
      return Base64.encode(Bytes.ofString(key));
    }

}



enum State {
  Handshake;
  ServerHandshake;
  Head;
  HeadExtraLength;
  HeadExtraMask;
  Body;
  Closed;
}


@:enum abstract WebSocketCloseCode(Int) {
  var Normal = 1000;
  var Shutdown = 1001;
  var ProtocolError = 1002;
  var DataError = 1003;
  var Reserved1 = 1004;
  var NoStatus = 1005;
  var CloseError = 1006;
  var UTF8Error = 1007;
  var PolicyError = 1008;
  var TooLargeMessage = 1009;
  var ClientExtensionError = 1010;
  var ServerRequestError = 1011;
  var TLSError = 1015;
}


@:enum abstract Opcode(Int) {
  var Continuation = 0x00;
  var Text = 0x01;
  var Binary = 0x02;
  var Close = 0x08;
  var Ping = 0x09;
  var Pong = 0x0A;

  @:to public function toInt() {
    return this;
  }
}


class Utf8Encoder {
  static public function encode(str:String):Bytes {
    // @TODO: Proper utf8 encoding!
    return Bytes.ofString(str);
  }

  static public function decode(data:Bytes):String {
    // @TODO: Proper utf8 decoding!
    return data.toString();
  }
}
