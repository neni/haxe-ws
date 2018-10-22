package haxe.net.impl;

import haxe.Constraints.Function;
import haxe.io.Bytes;
import haxe.io.Error;
import sys.net.Host;
import sys.net.Socket;


class SocketSys extends Socket2 {

  private var impl:sys.net.Socket;
  private var sendConnect:Bool = false;
  private var sendError:Bool = false;
  private var wasCloseSent:Bool = false;
  private var secure:Bool;
  private var isClosed:Bool = false;


  private function new(host:String, port:Int){
    super(host, port);
  }


  private function initialize(secure:Bool) {
    this.secure = secure;
    var impl:Dynamic = null;
    if (secure) {
      #if (haxe_ver >= "3.3")
        this.impl = new sys.ssl.Socket();
      #else
        throw 'Not supporting secure sockets';
      #end
    } else {
      this.impl = new sys.net.Socket();
    }
    try {
      this.impl.connect(new Host(host), port);
      this.impl.setFastSend(true);
      //this.impl.setBlocking(false);
      this.impl.setBlocking(false);
      //this.impl.setBlocking(true);
      this.sendConnect = true;
      #if debug
        trace('socket.connected!');
      #end
    } catch (e:Dynamic) {
        this.sendError = true;
        #if debug
          trace('socket.error! $e');
        #end
    }

    return this;
  }


  public static function create(host:String, port:Int, secure:Bool) {
    return new SocketSys(host, port).initialize(secure);
  }


  static function createFromExistingSocket(socket:sys.net.Socket) {
    var socketSys = new SocketSys(socket.host().host.host, socket.host().port);
    socket.setBlocking(false);
    socketSys.impl = socket;
    socketSys.secure = false;
    return socketSys;
  }


  override public function close() {
    this.impl.close();
    if (!wasCloseSent) {
      wasCloseSent = true;
      #if debug
        trace('socket.onclose!');
      #end
      onclose();
    }
  }


  override public function process() {
    if (sendConnect) {
      #if debug
        trace('socket.onconnect!');
      #end
      sendConnect = false;
      onconnect();
    }

    if (sendError) {
      #if debug
        trace('socket.onerror!');
      #end
      sendError = false;
      onerror();
    }

    var needClose = false;
    var result = null;
    try {
      result = sys.net.Socket.select([this.impl], [this.impl], [this.impl], 0.4);
    }catch (e:Dynamic) {
      #if debug
        trace('closing socket because of $e');
      #end
      needClose = true;
    }

    if(result != null && !needClose) {
      if (result.read.length > 0) {
        var out = new BytesRW();
        try {
          var input = this.impl.input;
          while (true) {
            var data = Bytes.alloc(1024);
            var readed = input.readBytes(data, 0, data.length);
            if (readed <= 0) break;
            out.writeBytes(data.sub(0, readed));
          }
        } catch (e:Dynamic) {
          needClose = !(e == 'Blocking' || (Std.is(e, Error) && (
              (e:Error).match(Error.Custom(Error.Blocked)) ||
              (e:Error).match(Error.Blocked))
          ));
          #if debug
            if(needClose) trace('closing socket because of $e');
          #end
        }
        ondata(out.readAllAvailableBytes());
      }
    }

    if (needClose) {
      close();
    }
  }


  override public dynamic function onconnect() {
  }


  override public dynamic function onclose() {
  }


  override public dynamic function onerror() {
  }


  override public dynamic function ondata(data:Bytes) {
  }


  override public function send(data:Bytes) {
    //trace('sending:$data');
    var output:haxe.io.Output = this.impl.output;
    output.write(data);
    output.flush();
    //this.impl.write
  }


}
