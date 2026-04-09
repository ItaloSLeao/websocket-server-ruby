# WebSocket Server from Scratch in Ruby ♦️

Este repositório contém a implementação de um servidor **WebSocket** desenvolvido em **Ruby**, com foco no entendimento profundo de comunicação em tempo real e protocolos de rede. 
O projeto foi construído sem o uso de bibliotecas de alto nível, manipulando diretamente sockets TCP e o handshake do protocolo WebSocket.

## Objetivo

O projeto demonstra a construção de um servidor WebSocket funcional, capaz de estabelecer conexões persistentes com clientes e permitir comunicação bidirecional em tempo real.

A implementação busca simular o comportamento de servidores modernos utilizados em aplicações como chats, jogos online e sistemas de notificação ao vivo.

## Funcionalidades Implementadas

- ### Servidor WebSocket nativo:  
  Implementação direta sobre sockets TCP, sem frameworks ou gems externas.

- ### Handshake WebSocket:
  Processamento completo do upgrade de conexão HTTP → WebSocket, incluindo:
  - Leitura dos headers
  - Geração do `Sec-WebSocket-Accept`
  - Resposta conforme especificação do protocolo

- ### Comunicação bidirecional:  
  Permite troca de mensagens em tempo real entre cliente e servidor.

- ### Parsing de frames WebSocket:
  Parsing manual dos frames, incluindo:
  - Máscara (masking)
  - Payload length
  - Opcode

- ### Logs de conexão:
  Registro de eventos importantes como:
  - Conexões abertas
  - Mensagens recebidas
  - Encerramento de conexões
