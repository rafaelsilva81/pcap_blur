## TODO

- [ ] Logs

  - [ ] Arquivo de metadados
  - [ ] Informações para guardar no arquivo de metadados
    - [ ] Pacotes com chekcsums errados
    - [ ] Pacotes truncados
    - [ ] Quantidade e frequência de vendor codes (pacotes com endereços MACs de fabricantes) (não mostrar os endereços originais)
    - [ ] Lista dos prefixo anonimizados e tamanho de cada subnet interna
    - [ ] Endereços IP de scanners anonimizados (para identificar qtd de scanners)
    - [ ] Numero total de pacotes anonimizados
    - [ ] Numero total de pacotes não anonimizados (caso haja)
    - [ ] Numero total de pacotes com erros (caso haja)
    - [ ] Checksum final do arquivo para garantir integridade entre o arquivo de metadados e o arquivo gerado pelo programa

- [ ] Validação
- [ ] Encontrar casos de exceção

  - [ ] Caso de exceção: TLS

    - [ ] Ignorar e não anonimizar a camada de aplicação pois não há a necessidade
    - [ ] Buscar explicar a importancia do TLS e dar motivos para não anonimizar

  - [ ] Caso de exceção: Scanners
    - [ ] Pesquisar o que fazer nessa situação
