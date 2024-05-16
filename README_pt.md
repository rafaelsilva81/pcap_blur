# Pcap_Blur

### [PT-BR](README_pt.md)

`pcap_blur` é uma ferramenta de linha de comando para anonimizar o tráfego de rede capturado em arquivos `.pcap` ou `.pcapng` de forma simples e segura. O objetivo principal desta ferramenta é permitir que qualquer pessoa anonimize sua própria tráfego de rede para pesquisa, testes ou fins educacionais. O foco principal de `pcap_blur` é na anonimização de tráfego de Internet sob a pilha TCP/IP.

## Instalação

### Windows

1. Baixe e instale o [Python 3.10 ou posterior](https://www.python.org/downloads/windows/) e o [pip](https://pypi.org/project/pip/)

2. Baixe e instale a última versão do [Npcap](https://nmap.org/npcap/)

> É recomendado **desativar** a opção `Winpcap compatibility mode` durante a instalação

3. Instale o `pcap_blur` usando o `pip`:

```bash
pip install pcap_blur
```

### Linux

1. Instale o [Python 3.10 ou posterior](https://www.python.org/downloads/) e o [pip](https://pypi.org/project/pip/)

2. Instale o [libpcap](https://www.tcpdump.org/)

Para distribuições Debian/Ubuntu:

```bash
sudo apt install libpcap-dev
```

Para distribuições Fedora/Red Hat:

```bash
sudo yum install libpcap-devel
```

3. Instale o `pcap_blur` usando o `pip`:

```bash
pip install pcap_blur
```

## Como usar

O principal uso do `pcap_blur` é anonimizar um arquivo `.pcap`. Para fazer isso, você pode usar o seguinte comando:

```bash
pcap_blur path/to/file.pcap
```

Por padrão, o arquivo de saída será chamado `file_anonymized.pcap` e junto com o arquivo de log será salvo em um diretório chamado `output`. Você pode alterar o diretório de saída e o nome do arquivo usando as opções `--outDir` e `--outName`, respectivamente.

```bash
pcap_blur path/to/file.pcap --outDir /new_output_folder --outName new_name.pcap
```

Você também pode usar a opção `--batch` para anonimizar vários arquivos em um diretório.

```bash
pcap_blur --batch /path/to/folder
```

Usando esta opção, um diretório `output` será criado no diretório especificado e os arquivos anonimizados serão salvos nele. Todos os logs serão salvos individualmente em um diretório `output/logs`. Você pode alterar o diretório de saída usando a opção `--outDir`.

```bash
pcap_blur --batch /path/to/folder --outDir /new_output_folder
```

Você também pode usar a opção `--validate` para validar a anonimização de um arquivo `.pcap`. Essa opção irá comparar o arquivo original e o arquivo anonimizado e procurar se qualquer informação original é encontrada no arquivo anonimizado.

```bash
pcap_blur --validate path/to/original_file.pcap path/to/anonymized_file.pcap
```

A tabela abaixo contém todas as opções de linha de comando disponíveis para o `pcap_blur`:

| Opção                                                    | Descrição                                                                                          | Valor Padrão                                                   |
| -------------------------------------------------------- | -------------------------------------------------------------------------------------------------- | -------------------------------------------------------------- |
| `path`                                                   | Caminho para o arquivo de captura a ser anonimizado.                                               | Nenhum                                                         |
| `--batch`                                                | Especifica um diretório para anonimização em lote.                                                 | Nenhum                                                         |
| `--outDir ${directory}`                                  | Configura o diretório de saída para os arquivos anonimizados.                                      | `output` ou `${original_folder}/output` se usado com `--batch` |
| `--outName ${filename}`                                  | Configura o nome do arquivo anonimizado. Pode ser usado apenas na anonimização de arquivos únicos. | `${original_filename}_anonymized.pcap`                         |
| `--version`                                              | Mostra a versão atual da ferramenta.                                                               | Nenhum                                                         |
| `--validate ${original_filename} ${anonymized_filename}` | Valida a anonimização de um arquivo `.pcap`.                                                       | Nenhum                                                         |
