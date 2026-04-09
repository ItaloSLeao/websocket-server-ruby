require 'socket'
require 'digest/sha1'  #fornece SHA1 para o handshake WebSocket

server = TCPServer.new('localhost', 2345)

loop do
  socket = server.accept
  STDERR.puts "Incoming Request"

  http_request = "" #vai acumular as linhas da req http

  while (line = socket.gets) && (line != "\r\n") #enquanto receber linhas e nao for vazia, acumula
    http_request += line
  end

  STDERR.puts http_request #imprime a req http

  if matches = http_request.match(/^Sec-WebSocket-Key: (\S+)/) #se a req. é reconhecida pelo regex (websocket)
    #captura caracteres nao espaco dentro de {(\s+)} em matches[1]

    websocket_key = matches[1] #chave de seguranca
    STDERR.puts "Websocket handshake detected with key: #{websocket_key}"
  else
    STDERR.puts "Aborting non websocket connection"
    socket.close
    next #como a conex. nao eh ws, pula pra proxima iteracao do loop
  end

  response_key = Digest::SHA1.base64digest( #combina a chave com a guid para o server provar q entendeu a req.
    [websocket_key, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"].join #calcula o hash sha1 e retorna em base64
  )

  STDERR.puts "Responding to handshake with key: #{response_key}"

  #server responde 101 para trocar de protocolo
  socket.write "HTTP/1.1 101 Switching Protocols\r\n"
  socket.write "Upgrade: websocket\r\n"
  socket.write "Connection: Upgrade\r\n"
  socket.write "Sec-WebSocket-Accept: #{response_key}\r\n"
  socket.write "\r\n"

  STDERR.puts "Handshake completed. Starting to parse the websocket frame." #termina o http e comeca o ws

  loop do #le frames continuamente, em bytes binarios

    first_byte = socket.getbyte
    break if first_byte.nil? #encerra se fb eh nulo

    fin = first_byte & 0b10000000 #isola o bit mais significativo

    opcode = first_byte & 0b00001111 #isola os 4 lsb, definindo o tipo de frame
    break if opcode == 8 #close frame

    raise "We don't support continuations" unless fin #excecao se fin nao for true
    raise "We only support opcode 1" unless opcode == 1 #so suporta msg de texto

    #parsing e response -------------------------------

    second_byte = socket.getbyte
    is_masked = second_byte & 0b10000000 #mascara o payload, padrao cliente -> servidor
    payload_size = second_byte & 0b01111111

    raise "All frames sent to a server should be masked" unless is_masked
    raise "We only support payloads < 126 bytes"         unless payload_size < 126

    STDERR.puts "Payload size: #{payload_size} bytes"

    mask = 4.times.map { socket.getbyte } #cria um array com os 4 bytes da mascara
    STDERR.puts "Got mask: #{mask.inspect}"

    data = payload_size.times.map { socket.getbyte } #cria um array com os bytes de payload
    STDERR.puts "Got masked data: #{data.inspect}"

    #desmascara fazendo xor de cada byte mask com o byte correspondente do payload
    unmasked_data = data.each_with_index.map { |byte, i| byte ^ mask[i % 4] }
    STDERR.puts "Unmasked the data: #{unmasked_data.inspect}"

    #converte o array de inteiros (bytes) para uma string utf-8
    message = unmasked_data.pack('C*').force_encoding('utf-8')
    STDERR.puts "Received message: #{message.inspect}"

    response = "Kaizoku Ō ni, ore wa naru!"
    STDERR.puts "Sending response: #{response.inspect}"

    #monta o frame WebSocket de resposta como array de bytes
    output = [0b10000001, response.bytesize, response]

    socket.write output.pack("CCA#{response.bytesize}")

  end

  socket.close
  STDERR.puts "Connection closed."
  
end