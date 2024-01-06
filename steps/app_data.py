from scapy.all import Packet, Raw

"""
  Esse passo anonimiza os dados da camada de aplicação.
  De acordo com o que foi definido no trabalho de pesquisa,
  os dados da camada de aplicação serão substituídos por 
  uma sequência de bytes nulos (0x00) utilizando o algortimo de black marker.

  Args:
    packet: pacote a ser anonimizado
  Output:
    packet: pacote com os dados da camada de aplicação anonimizados
"""
def anon_app_data(packet: Packet) -> Packet:
    if Raw in packet:
      payload_length = len(packet[Raw].load)
      packet[Raw].load = b"\x00"
    return packet
 