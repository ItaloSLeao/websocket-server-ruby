# server.rb
require 'socket'       # biblioteca padrão do Ruby — fornece TCPServer e TCPSocket
require 'digest/sha1'  # biblioteca padrão do Ruby — fornece SHA1 para o handshake WebSocket

server = TCPServer.new('localhost', 2345)
# Abre um servidor TCP na porta 2345
# Fica "ouvindo" conexões nessa porta — nenhum outro programa pode usá-la simultaneamente

loop do
  # Loop infinito — o servidor processa uma conexão por vez (sem threads aqui, diferente da nossa network stack)

  socket = server.accept
  # BLOQUEIA aqui até alguém conectar
  # Quando o navegador acessa ws://localhost:2345, essa linha retorna o socket do cliente

  STDERR.puts "Incoming Request"
  # STDERR é o canal de saída de erros/logs — separado do STDOUT
  # Usar STDERR para logs é uma boa prática: permite redirecionar logs separadamente do output principal

  # === LEITURA DA REQUISIÇÃO HTTP INICIAL ===
  # WebSockets começam como uma requisição HTTP normal — depois "sobem" para o protocolo WS
  # Precisamos ler essa requisição HTTP inicial para extrair a chave de segurança

  http_request = ""
  # String vazia que vai acumular as linhas da requisição HTTP

  while (line = socket.gets) && (line != "\r\n")
    http_request += line
    # Lê linha por linha até encontrar a linha em branco (\r\n sozinho)
    # A linha em branco indica o fim dos headers HTTP — igual ao que implementamos na network stack
  end

  STDERR.puts http_request
  # Imprime a requisição HTTP completa no terminal para debug
  # Você verá os headers como: Upgrade: websocket, Sec-WebSocket-Key: xxx, etc.

  # === VERIFICAÇÃO DO HANDSHAKE WEBSOCKET ===
  # Nem toda requisição que chega é WebSocket — pode ser um browser acessando normalmente
  # Verificamos se o header Sec-WebSocket-Key está presente

  if matches = http_request.match(/^Sec-WebSocket-Key: (\S+)/)
    # .match() testa a string contra a regex e retorna um MatchData ou nil
    # /^Sec-WebSocket-Key: (\S+)/
    #   ^         → início da linha
    #   \S+       → um ou mais caracteres não-espaço (captura a chave)
    #   ()        → grupo de captura — o que estiver aqui fica em matches[1]

    websocket_key = matches[1]
    # matches[0] = string completa que casou
    # matches[1] = primeiro grupo de captura = a chave em si
    # Ex: "cG8zEwcrcLnEftn2qohdKQ=="

    STDERR.puts "Websocket handshake detected with key: #{websocket_key}"
  else
    STDERR.puts "Aborting non-websocket connection"
    socket.close  # fecha a conexão com esse cliente
    next          # pula para a próxima iteração do loop — espera próxima conexão
  end

  # === GERAÇÃO DA CHAVE DE RESPOSTA ===
  # O protocolo WebSocket exige que o servidor prove que entendeu a requisição
  # Para isso, combina a chave do cliente com uma "magic string" definida na RFC 6455
  # e retorna o SHA1 disso em base64

  response_key = Digest::SHA1.base64digest(
    [websocket_key, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"].join
    # .join concatena os dois elementos do array em uma string única
    # "258EAFA5-E914-47DA-95CA-C5AB0DC85B11" é a magic string da especificação WebSocket
    # SHA1.base64digest() calcula o hash SHA1 e já retorna em formato base64
  )

  STDERR.puts "Responding to handshake with key: #{response_key}"

  # === ENVIO DO HANDSHAKE DE RESPOSTA ===
  # O servidor responde com HTTP 101 Switching Protocols
  # 101 significa "ok, vou trocar de protocolo — de HTTP para WebSocket"
  # CRÍTICO: os headers não podem ter indentação — HTTP é sensível a isso

  socket.write "HTTP/1.1 101 Switching Protocols\r\n"
  # Status line: versão HTTP + código 101 + descrição
  # \r\n é obrigatório em HTTP — carriage return + newline

  socket.write "Upgrade: websocket\r\n"
  # Confirma que está fazendo upgrade para WebSocket

  socket.write "Connection: Upgrade\r\n"
  # Confirma que a conexão está sendo "promovida"

  socket.write "Sec-WebSocket-Accept: #{response_key}\r\n"
  # Envia a chave de resposta calculada — o navegador valida isso
  # Se a chave estiver errada, o navegador rejeita a conexão

  socket.write "\r\n"
  # Linha em branco obrigatória — indica fim dos headers
  # Após isso, o protocolo HTTP termina e começa o protocolo WebSocket

  STDERR.puts "Handshake completed. Starting to parse the websocket frame."

  # === PARSING DO FRAME WEBSOCKET ===
  # A partir daqui, HTTP acabou — os dados chegam no formato binário de frames WebSocket
  # Um frame WebSocket tem uma estrutura específica de bytes definida na RFC 6455

  # --- BYTE 1 ---
  first_byte = socket.getbyte
  # .getbyte lê exatamente 1 byte do socket como inteiro (0-255)
  # Diferente de .gets que lê texto — aqui estamos no protocolo binário

  fin = first_byte & 0b10000000
  # & é operador AND bit a bit (bitwise AND)
  # 0b10000000 é máscara binária que isola apenas o bit mais significativo (bit 7)
  # FIN = 1 significa que este é o frame final da mensagem
  # FIN = 0 significa que a mensagem continua em frames seguintes (continuação)
  # Ex: first_byte = 0b10000001 → fin = 0b10000000 (não zero = verdadeiro)

  opcode = first_byte & 0b00001111
  # Máscara que isola os 4 bits menos significativos (bits 0-3)
  # opcode define o tipo do frame:
  #   0 = continuação
  #   1 = texto (UTF-8)  ← o que esperamos
  #   2 = binário
  #   8 = fechar conexão
  #   9 = ping
  #   10 = pong

  raise "We don't support continuations" unless fin
  # raise lança uma exceção — equivalente ao throw do Java
  # unless é o oposto de if — "lança exceção A MENOS QUE fin seja verdadeiro"

  raise "We only support opcode 1" unless opcode == 1
  # Nosso servidor só suporta mensagens de texto (opcode 1)

  # --- BYTE 2 ---
  second_byte = socket.getbyte

  is_masked = second_byte & 0b10000000
  # Isola o bit MASK — se 1, o payload está mascarado
  # A especificação WebSocket EXIGE que frames do cliente para o servidor sejam mascarados
  # Frames do servidor para o cliente NUNCA são mascarados

  payload_size = second_byte & 0b01111111
  # Isola os 7 bits do tamanho do payload
  # Se < 126: esse valor É o tamanho
  # Se = 126: os próximos 2 bytes contêm o tamanho real
  # Se = 127: os próximos 8 bytes contêm o tamanho real
  # Nosso servidor só suporta payloads pequenos (< 126 bytes)

  raise "All frames sent to a server should be masked" unless is_masked
  raise "We only support payloads < 126 bytes"         unless payload_size < 126

  STDERR.puts "Payload size: #{payload_size} bytes"

  # --- BYTES 3-6: CHAVE DE MASCARAMENTO ---
  mask = 4.times.map { socket.getbyte }
  # Lê 4 bytes — a chave de mascaramento
  # 4.times.map cria um array executando o bloco 4 vezes
  # Cada iteração lê 1 byte do socket
  # Resultado: array de 4 inteiros ex: [80, 191, 161, 254]

  STDERR.puts "Got mask: #{mask.inspect}"
  # .inspect mostra o array de forma legível: "[80, 191, 161, 254]"

  # --- BYTES SEGUINTES: PAYLOAD MASCARADO ---
  data = payload_size.times.map { socket.getbyte }
  # Lê exatamente payload_size bytes — o conteúdo mascarado da mensagem
  # Parece lixo binário — precisa ser desmascarado antes de usar

  STDERR.puts "Got masked data: #{data.inspect}"

  # === DESMASCARAMENTO ===
  # Para desmascarar: XOR de cada byte do payload com o byte correspondente da mask
  # A mask tem 4 bytes, então repete ciclicamente usando módulo 4
  # XOR (^) é reversível: (A ^ B) ^ B = A

  unmasked_data = data.each_with_index.map { |byte, i| byte ^ mask[i % 4] }
  # .each_with_index itera passando o elemento E seu índice para o bloco
  # |byte, i| → byte = valor do byte, i = índice (0, 1, 2, ...)
  # byte ^ mask[i % 4] → XOR do byte com o byte da mask na posição correta
  # i % 4 garante que o índice da mask cicla: 0,1,2,3,0,1,2,3...

  STDERR.puts "Unmasked the data: #{unmasked_data.inspect}"

  # Converte o array de inteiros (bytes) para uma String UTF-8
  message = unmasked_data.pack('C*').force_encoding('utf-8')
  # .pack('C*') converte array de inteiros para string binária
  #   'C' = unsigned char (1 byte por elemento)
  #   '*' = repete para todos os elementos
  # .force_encoding('utf-8') diz ao Ruby como interpretar os bytes
  # Resultado: "Can you hear me?"

  STDERR.puts "Received message: #{message.inspect}"

  # === ENVIANDO RESPOSTA DE VOLTA AO CLIENTE ===
  response = "Loud and clear!"
  STDERR.puts "Sending response: #{response.inspect}"

  # Monta o frame WebSocket de resposta como array de bytes
  output = [0b10000001, response.size, response]
  # 0b10000001 → Byte 1: FIN=1 (frame final) + opcode=1 (texto)
  # response.size → Byte 2: tamanho do payload SEM bit de máscara
  #                 (servidor → cliente nunca é mascarado — bit MASK = 0)
  # response → o payload em si (string de texto)

  socket.write output.pack("CCA#{response.size}")
  # .pack converte o array para bytes prontos para envio
  # "CC" → dois unsigned chars (os dois primeiros bytes do frame)
  # "A#{response.size}" → string de caracteres ASCII com tamanho fixo
  # O navegador recebe isso, desempacota o frame e entrega "Loud and clear!" ao onmessage

  STDERR.puts "Response sent. Closing connection."
  socket.close
  # Fecha a conexão WebSocket após enviar a resposta
  # Um servidor real manteria a conexão aberta para mensagens contínuas
end