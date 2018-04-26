 # ! / usr / bin / env python

import sys
import httplib
de importação SocketServer ThreadingMixIn
de BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
de bloqueio de importação de segmentação , temporizador
de cStringIO import StringIO
from urlparse import urlsplit
soquete de importação
importar seleto
importar gzip
import zlib
importação re
traceback de importação


Classe  ThreadingHTTPServer ( ThreadingMixIn , HTTPServer ):

    address_family = socket. AF_INET

    def  handle_error ( self , request , client_address ):
        
        imprimir  >> sys.stderr, ' - ' * 40
        print  >> sys.stderr, ' Exceção ocorreu durante o processamento da solicitação de ' , client_address
        traceback.print_exc ()
        imprimir  >> sys.stderr, ' - ' * 40
        
     
classe  ThreadingHTTPServer6 ( ThreadingHTTPServer ):

    address_family = socket. AF_INET6


classe  SimpleHTTPProxyHandler ( BaseHTTPRequestHandler ):
    global_lock = Lock ()
    conn_table = {}
    tempo limite =  300               
    upstream_timeout =  300    
    proxy_via =  Nenhum          

    def  log_error ( self , format , * args ):
        if  format  ==  " Solicitação expirada: % r " :
            Retorna
        self .log_message ( format , * args)

    def  do_CONNECT ( self ):
        

        req =  self
        reqbody =  Nenhum
        req.path =  " https: // % s / "  % req.path.replace ( ' : 443 ' , ' ' )

        replaced_reqbody =  self .request_handler (req, reqbody)
        se replaced_reqbody for  True :
            Retorna

        u = urlsplit (req.path)
        address = (u.hostname, u.port or 443)
        try:
            conn = socket.create_connection(address)
        except socket.error:
            return
        self.send_response(200, '<font color="red">PROXY SOCKS</font> <font color="blue">#Bolsonaro2018</font>')
        self.send_header('Connection', 'close')
        self.end_headers()

        conns = [self.connection, conn]
        keep_connection = True
        while keep_connection:
            keep_connection = False
            rlist, wlist, xlist = select.select(conns, [], conns, self.timeout)
            if xlist:
                break
            for r in rlist:
                other = conns[1] if r is conns[0] else conns[0]
                data = r.recv(8192)
                if data:
                    other.sendall(data)
                    keep_connection = True
        conn.close()

    def do_HEAD(self):
        self.do_SPAM()

    def do_GET(self):
        self.do_SPAM()

    def do_POST(self):
        self.do_SPAM()

    def do_SPAM(self):
        req = self
        content_length = int(req.headers.get('Content-Length', 0))
        if content_length > 0:
            reqbody = self.rfile.read(content_length)
        else:
            reqbody = None

        replaced_reqbody = self.request_handler(req, reqbody)
        if replaced_reqbody is True:
            return
        elif replaced_reqbody is not None:
            reqbody = replaced_reqbody
            if 'Content-Length' in req.headers:
                req.headers['Content-Length'] = str(len(reqbody))

        
        self.remove_hop_by_hop_headers(req.headers)
        if self.upstream_timeout:
            req.headers['Connection'] = 'Keep-Alive'
        else:
            req.headers['Connection'] = 'close'
        if self.proxy_via:
            self.modify_via_header(req.headers)

        try:
            res, resdata = self.request_to_upstream_server(req, reqbody)
        except socket.error:
            return

        content_encoding = res.headers.get('Content-Encoding', 'identity')
        resbody = self.decode_content_body(resdata, content_encoding)

        replaced_resbody = self.response_handler(req, reqbody, res, resbody)
        if replaced_resbody is True:
            return
        elif replaced_resbody is not None:
            resdata = self.encode_content_body(replaced_resbody, content_encoding)
            if 'Content-Length' in res.headers:
                res.headers['Content-Length'] = str(len(resdata))
            resbody = replaced_resbody

        self.remove_hop_by_hop_headers(res.headers)
        if self.timeout:
            res.headers['Connection'] = 'Keep-Alive'
        else:
            res.headers['Connection'] = 'close'
        if self.proxy_via:
            self.modify_via_header(res.headers)

        self.send_response(res.status, res.reason)
        for k, v in res.headers.items():
            if k == 'set-cookie':
                
                for value in self.split_set_cookie_header(v):
                    self.send_header(k, value)
            else:
                self.send_header(k, v)
        self.end_headers()

        if self.command != 'HEAD':
            self.wfile.write(resdata)
            with self.global_lock:
                self.save_handler(req, reqbody, res, resbody)

    def request_to_upstream_server(self, req, reqbody):
        u = urlsplit(req.path)
        origin = (u.scheme, u.netloc)

        
        req.headers['Host'] = u.netloc
        selector = "%s?%s" % (u.path, u.query) if u.query else u.path

        while True:
            with self.lock_origin(origin):
                conn = self.open_origin(origin)
                try:
                    conn.request(req.command, selector, reqbody, headers=dict(req.headers))
                except socket.error:
                    
                    self.close_origin(origin)
                    raise
                try:
                    res = conn.getresponse(buffering=True)
                except httplib.BadStatusLine as e:
                    if e.line == "''":
                        
                        self.close_origin(origin)
                        continue
                    else:
                        raise
                resdata = res.read()
                res.headers = res.msg    
                if not self.upstream_timeout or 'close' in res.headers.get('Connection', ''):
                    self.close_origin(origin)
                else:
                    self.reset_timer(origin)
            return res, resdata

    def lock_origin(self, origin):
        d = self.conn_table.setdefault(origin, {})
        if not 'lock' in d:
            d['lock'] = Lock()
        return d['lock']

    def open_origin(self, origin):
        conn = self.conn_table[origin].get('connection')
        if not conn:
            scheme, netloc = origin
            if scheme == 'https':
                conn = httplib.HTTPSConnection(netloc)
            else:
                conn = httplib.HTTPConnection(netloc)
            self.reset_timer(origin)
            self.conn_table[origin]['connection'] = conn
        return conn

    def reset_timer(self, origin):
        timer = self.conn_table[origin].get('timer')
        if timer:
            timer.cancel()
        if self.upstream_timeout:
            timer = Timer(self.upstream_timeout, self.close_origin, args=[origin])
            timer.daemon = True
            timer.start()
        else:
            timer = None
        self.conn_table[origin]['timer'] = timer

    def close_origin(self, origin):
        timer = self.conn_table[origin]['timer']
        if timer:
            timer.cancel()
        conn = self.conn_table[origin]['connection']
        conn.close()
        del self.conn_table[origin]['connection']

    def remove_hop_by_hop_headers(self, headers):
        hop_by_hop_headers = ['Connection', 'Keep-Alive', 'Proxy-Authenticate', 'Proxy-Authorization', 'TE', 'Trailers', 'Trailer', 'Transfer-Encoding', 'Upgrade']
        connection = headers.get('Connection')
        if connection:
            keys = re.split ( r ' , \ s * ' , conexão)
            hop_by_hop_headers.extend (chaves)

        para k em hop_by_hop_headers:
            se k nos cabeçalhos:
                del cabeçalhos [k]

    def  modify_via_header ( auto , cabeçalhos ):
        via_string =  " % s  % s "  % ( self .protocol_version, self .proxy_via)
        via_string = re.sub ( r ' ^ HTTP / ' , ' ' , via_string)

        original = headers.get ( ' Via ' )
        se original:
            cabeçalhos [ ' Via ' ] = original +  ' , '  + via_string
        else :
            cabeçalhos [ ' Via ' ] = via_string

    def  decode_content_body ( self , data , content_encoding ):
        if content_encoding in ( ' gzip ' , ' x-gzip ' ):
            io = StringIO (dados)
            com gzip.GzipFile ( fileobj = io) como f:
                body = f.read ()
        elif content_encoding ==  ' deflate ' :
            body = zlib.decompress (data)
        elif content_encoding ==  ' identidade ' :
            corpo = dados
        else :
            raise  Exception ( " Conteúdo Desconhecido-Codificação: % s "  % content_encoding)
        retorno corporal

    def  cod_content_body ( self , body , content_encoding ):
        if content_encoding in ( ' gzip ' , ' x-gzip ' ):
            io = StringIO ()
            com gzip.GzipFile ( fileobj = io, mode = ' wb ' ) como f:
                f.write (corpo)
            data = io.getvalue ()
        elif content_encoding ==  ' deflate ' :
            data = zlib.compress (corpo)
        elif content_encoding ==  ' identidade ' :
            dados = corpo
        else :
            raise  Exception ( " Conteúdo Desconhecido-Codificação: % s "  % content_encoding)
        dados de retorno

    def  split_set_cookie_header ( self , value ):
        re_cookies =  r ' ( [ ^ = ] + = [ ^ ,; ] + (?: ; \ s * Expira = [ ^ , ] + , [ ^ ,; ] + | ; [ ^ ,; ] + ) * ) ( ?: , \ s * ) ? '
        return re.findall (re_cookies, valor, bandeiras = re. IGNORECASE )

    def  request_handler ( self , req , reqbody ):
        
        passar

    def  response_handler ( auto , req , reqbody , res , resbody ):
     
        passar

    def  save_handler ( auto , req , reqbody , res , resbody ):
     
        passar




def  teste ( HandlerClass = SimpleHTTPProxyHandler, ServerClass = ThreadingHTTPServer, protocolo = " HTTP / 1.1 " ):
    if sys.argv [ 1 :]:
        port =  int (sys.argv [ 1 ])
    else :
        porta =  80
    server_address = ( ' ' , porta)

    HandlerClass.protocol_version = protocol
    httpd = ServerClass (server_address, HandlerClass)

    sa = httpd.socket.getsockname ()
    print  " Servindo HTTP em " , sa [ 0 ], " port " , sa [ 1 ], " ... "
    httpd.serve_forever ()


se  __name__  ==  ' __main__ ' :
    teste()